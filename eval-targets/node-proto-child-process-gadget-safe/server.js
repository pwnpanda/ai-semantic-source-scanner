const { spawn } = require("node:child_process");

const job = Object.create(null);
spawn(job.command, job.args || []);
