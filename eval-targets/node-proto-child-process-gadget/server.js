const { spawn } = require("node:child_process");

const job = {};
spawn(job.command, job.args || []);
