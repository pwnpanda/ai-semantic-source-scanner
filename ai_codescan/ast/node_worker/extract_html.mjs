export async function* run(job) {
  yield { type: "stub", kind: "html", filesRequested: job.files.length };
}
