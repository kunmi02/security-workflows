import { createHash } from 'node:crypto';
import { appendFile, readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const levels = ['low', 'moderate', 'high', 'critical'];
const findingLabel = 'security-finding';
const suppressionLabel = 'security-false-positive';
const markerPattern = /<!-- port-finding:npm-v1:([a-f0-9]{64}) -->/g;

export function readAdvisories(report) {
  if (report?.error || report?.auditReportVersion !== 2 ||
      !report.vulnerabilities || typeof report.vulnerabilities !== 'object' ||
      Array.isArray(report.vulnerabilities)) {
    throw new Error('npm audit did not produce a valid version 2 report');
  }

  const advisories = [];
  for (const vulnerability of Object.values(report.vulnerabilities)) {
    if (!Array.isArray(vulnerability?.via)) throw new Error('Invalid npm audit entry');
    for (const advisory of vulnerability.via) {
      // String entries point to another package's advisory in this report.
      if (typeof advisory === 'string') continue;
      if (!Number.isSafeInteger(advisory?.source) ||
          typeof advisory.name !== 'string' || !advisory.name ||
          !levels.includes(advisory.severity)) {
        throw new Error('Advisory is missing a stable ID, package, or severity');
      }
      advisories.push(advisory);
    }
  }
  return advisories;
}

export function fingerprint(repositoryId, advisory) {
  // Preserve the original MatchVault frontend key for existing suppressions.
  const lockfile = process.env.AUDIT_LOCKFILE ?? 'package-lock.json';
  const scope = process.env.TARGET_REPOSITORY === 'kunmi02/matchvault' &&
    lockfile === 'frontend/package-lock.json' ? 'package-lock.json' : lockfile;
  return createHash('sha256').update(JSON.stringify([
    'npm-v1', repositoryId, scope, advisory.name, advisory.source,
  ])).digest('hex');
}

async function github(path, body) {
  const response = await fetch(new URL(path, process.env.GITHUB_API_URL), {
    method: body ? 'POST' : 'GET',
    headers: {
      authorization: `Bearer ${process.env.GH_TOKEN}`,
      accept: 'application/vnd.github+json',
      'content-type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error(`GitHub API returned ${response.status} for ${path}`);
  return response.json();
}

export async function publish(advisories, minimum, repositoryId, repository, request) {
  if (!levels.includes(minimum) || !/^\d+$/.test(repositoryId ?? '') ||
      !/^[\w.-]+\/[\w.-]+$/.test(repository ?? '')) {
    throw new Error('Invalid severity or GitHub repository configuration');
  }
  const issuesPath = `/repos/${repository}/issues`;
  const byFingerprint = new Map();
  for (let page = 1; ; page += 1) {
    const issues = await request(`${issuesPath}?state=all&per_page=100&page=${page}`);
    for (const issue of issues) {
      if (issue.pull_request || !issue.user?.login?.endsWith('[bot]') ||
          !issue.labels.some(label => label.name === findingLabel)) continue;
      const keys = [...(issue.body ?? '').matchAll(markerPattern)];
      if (keys.length !== 1) continue;
      const key = keys[0][1];
      if (byFingerprint.has(key)) {
        throw new Error(`Duplicate managed issues for ${key}. Reconcile them before publishing.`);
      }
      byFingerprint.set(key, issue);
    }
    if (issues.length < 100) break;
  }

  const totals = { created: 0, existing: 0, suppressed: 0, closedNeedsReview: 0 };
  const seen = new Set();
  for (const advisory of advisories) {
    if (levels.indexOf(advisory.severity) < levels.indexOf(minimum)) continue;
    const key = fingerprint(repositoryId, advisory);
    if (seen.has(key)) continue;
    seen.add(key);

    const issue = byFingerprint.get(key);
    if (issue) {
      // Refresh immediately before acting so a reviewer can triage during a scan.
      const current = await request(`${issuesPath}/${issue.number}`);
      if (current.labels.some(label => label.name === suppressionLabel)) {
        totals.suppressed += 1;
      } else if (current.state === 'closed') {
        totals.closedNeedsReview += 1;
        console.log(`Closed issue #${issue.number} was observed again. Review it in GitHub.`);
      } else {
        totals.existing += 1;
      }
      continue;
    }

    await request(issuesPath, {
      title: `[Dependency finding] ${advisory.name} / npm advisory ${advisory.source}`,
      labels: [findingLabel],
      body: [
        `<!-- port-finding:npm-v1:${key} -->`,
        `Package: ${advisory.name}`,
        `npm advisory: ${advisory.source}`,
        `Severity: ${advisory.severity}`,
        `Affected range: ${JSON.stringify(advisory.range ?? '')}`,
        `Component: ${process.env.AUDIT_LOCKFILE ?? "package-lock.json"}`,
        '',
        'Review applicability before assigning remediation. Keep the finding marker in this issue.',
      ].join('\n'),
    });
    totals.created += 1;
  }
  return totals;
}

async function main(args) {
  const validate = args[0] === '--validate';
  const advisories = readAdvisories(JSON.parse(await readFile(args[validate ? 1 : 0], 'utf8')));
  if (validate) return;

  const totals = await publish(
    advisories, process.env.MINIMUM_SEVERITY, process.env.TARGET_REPOSITORY_ID,
    process.env.TARGET_REPOSITORY, github,
  );
  const summary = Object.entries(totals).map(([name, count]) => `- ${name}: ${count}`).join('\n');
  console.log(summary);
  if (process.env.GITHUB_STEP_SUMMARY) {
    await appendFile(process.env.GITHUB_STEP_SUMMARY, `## Dependency findings\n\n${summary}\n`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main(process.argv.slice(2));
}
