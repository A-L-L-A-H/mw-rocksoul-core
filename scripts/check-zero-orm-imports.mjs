#!/usr/bin/env node
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FORBIDDEN_PATTERN = /@moonwitness\/orm-[a-z0-9-]*/giu;
const SCAN_DIRS = ['src', 'tests'];
const SCAN_FILES = ['package.json'];
const ALLOWED_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.mjs', '.cjs', '.json']);

/** @type {Array<{ file: string; line: number; match: string }>} */
const violations = [];
let scannedFileCount = 0;

/**
 * @param {string} absolutePath
 */
function inspectFile(absolutePath) {
  const relativePath = path.relative(ROOT_DIR, absolutePath).replaceAll('\\', '/');
  const content = readFileSync(absolutePath, 'utf8');
  scannedFileCount += 1;

  const lines = content.split(/\r?\n/u);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    const matches = line.match(FORBIDDEN_PATTERN);
    if (matches) {
      for (const match of matches) {
        violations.push({
          file: relativePath,
          line: i + 1,
          match,
        });
      }
    }
  }
}

/**
 * @param {string} dirPath
 */
function walkDirectory(dirPath) {
  let entries;
  try {
    entries = readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '.git') {
      continue;
    }
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      walkDirectory(fullPath);
    } else if (entry.isFile() && ALLOWED_EXTENSIONS.has(path.extname(entry.name))) {
      inspectFile(fullPath);
    }
  }
}

for (const dir of SCAN_DIRS) {
  walkDirectory(path.join(ROOT_DIR, dir));
}

for (const file of SCAN_FILES) {
  const fullPath = path.join(ROOT_DIR, file);
  try {
    if (statSync(fullPath).isFile()) {
      inspectFile(fullPath);
    }
  } catch {
    // ignore missing optional scan file
  }
}

if (violations.length > 0) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        scannedFiles: scannedFileCount,
        violationCount: violations.length,
        violations,
      },
      null,
      2
    )
  );
  process.exit(1);
}

console.log(
  JSON.stringify(
    {
      ok: true,
      scannedFiles: scannedFileCount,
      violationCount: 0,
      message: 'Zero @moonwitness/orm-* imports detected.',
    },
    null,
    2
  )
);
