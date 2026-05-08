export async function* run(job) {
  yield { type: "stub", kind: "treesitter", filesRequested: job.files.length };
}
