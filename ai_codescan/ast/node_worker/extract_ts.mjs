export async function* run(job) {
  yield { type: "stub", kind: "ts", filesRequested: job.files.length };
}
