"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const fsp = fs.promises;
const os = require("node:os");
const path = require("node:path");
const { pipeline } = require("node:stream/promises");
const { pack } = require("tar-stream");
const { downloadPacked, extractArchive, publish } = require("./packedDownload.cjs");

async function fixture(t) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "netcatty-pack-qa-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const stage = path.join(dir, "stage"), local = path.join(dir, "local"), file = path.join(dir, "archive");
  await fsp.mkdir(stage);
  await fsp.mkdir(local);
  return {
    dir, stage, local, file,
    async archive(items) {
      const archive = pack(), copying = pipeline(archive, fs.createWriteStream(file));
      for (const [header, contents] of items) archive.entry(header, contents ?? Buffer.alloc(0));
      archive.finalize();
      await copying;
    },
    extract(names) { return extractArchive(file, stage, false, names, new AbortController().signal); },
  };
}

test("hostile packed downloads reject traversal, malicious links, unexpected names, duplicate roots and special files", async t => {
  const directory = { name: "compose/", type: "directory" };
  for (const bad of [
    { name: "compose/../escape" }, { name: "/escape" }, { name: "other.txt" }, directory,
    { name: "compose/bad", type: "symlink", linkname: "../../escape" },
    { name: "compose/bad", type: "symlink", linkname: "/tmp" },
    { name: "compose/bad", type: "link", linkname: "compose/not-a-regular-file" },
    { name: "compose/bad", type: "fifo" },
  ]) {
    await t.test(bad.name + ":" + bad.type, async tt => {
      const f = await fixture(tt);
      await f.archive([[directory], [bad]]);
      await assert.rejects(f.extract(["compose"]), /archive|outside the downloaded selection|symbolic link|hard link|special file/i);
      assert.equal(fs.existsSync(path.join(f.dir, "escape")), false);
    });
  }
  await t.test("never follows a safe symlink for a later write", async tt => {
    const f = await fixture(tt);
    await f.archive([[directory], [{ name: "compose/real", type: "directory" }],
      [{ name: "compose/alias", type: "symlink", linkname: "real" }], [{ name: "compose/alias/injected" }, "oops"]]);
    await assert.rejects(f.extract(["compose"]), /unsafe parent/);
    assert.equal(fs.existsSync(path.join(f.stage, "compose", "real", "injected")), false);
  });
});

test("truncated archive with finished file data cannot publish", async t => {
  const f = await fixture(t);
  await f.archive([[{ name: "compose", type: "directory" }], [{ name: "compose/a" }, "data"]]);
  await fsp.truncate(f.file, (await fsp.stat(f.file)).size - 512);
  await assert.rejects(f.extract(["compose"]), /incomplete|unexpected end/i);
  assert.deepEqual(await fsp.readdir(f.local), []);
});

test("on default macOS volume, aliased names cannot overwrite independent files", { skip: process.platform !== "darwin" }, async t => {
  const f = await fixture(t);
  await fsp.writeFile(path.join(f.dir, "alias"), "");
  if (!fs.existsSync(path.join(f.dir, "ALIAS"))) { t.skip("case-sensitive volume"); return; }
  await f.archive([[{ name: "compose", type: "directory" }], [{ name: "compose/Config" }, "one"], [{ name: "compose/config" }, "two"]]);
  await assert.rejects(f.extract(["compose"]), {code: "EEXIST"});
  assert.equal(await fsp.readFile(path.join(f.stage, "compose", "Config"), "utf8"), "one");
});

test("rollback never deletes foreign files added to a concurrently published directory", async t => {
  const f = await fixture(t);
  await f.archive([[{ name: "a", type: "directory" }], [{ name: "a/owned" }, "app"], [{ name: "b", type: "directory" }]]);
  const manifest = await f.extract(["a", "b"]);
  const rename = fsp.rename.bind(fsp);
  t.mock.method(fsp, "rename", async (from, to) => {
    if (to === path.join(f.local, "b")) {
      await fsp.writeFile(path.join(f.local, "a", "other-app"), "external");
      await fsp.writeFile(path.join(f.local, "b", "other-app"), "external");
    }
    return rename(from, to);
  });
  assert.deepEqual(await publish(f.stage, f.local, ["a", "b"], new AbortController().signal, manifest), { status: "fallback", reason: "conflict" });
  for (const name of ["a", "b"]) {
    assert.deepEqual(await fsp.readdir(path.join(f.local, name)), ["other-app"]);
    assert.equal(await fsp.readFile(path.join(f.local, name, "other-app"), "utf8"), "external");
  }
});

test("SFTP-only and unrepresentable shell selections fall back before touching local or remote files", async t => {
  const f = await fixture(t);
  const requests = [["compose"], ["weird\nname"], Array.from({ length: 1001 }, (_, i) => String(i))];
  for (const names of requests) {
    const result = await downloadPacked({ client: { client: { exec: () => assert.fail("no archive command") } },
      payload: { sftpId: "s", names, remoteDirectory: "/srv", localDirectory: f.local, transferId: "restricted" },
      encoding: "utf-8", execProbe: async () => { throw new Error("Unable to exec"); } });
    assert.deepEqual(result, { status: "fallback", reason: "unsupported" });
  }
  assert.deepEqual(await fsp.readdir(f.local), []);
});
