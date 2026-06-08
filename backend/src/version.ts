// Version comparison.
//
// Two comparators, because network-service versions come in two flavours:
//   - upstream versions from banners:      "8.2p1", "2.4.49", "1.20.0"
//   - distro package revisions:            "1:8.2p1-4ubuntu0.11"
//
// The distro comparator implements Debian's actual dpkg algorithm (epoch,
// upstream, revision, with '~' sorting before everything and letters sorting
// before non-letters). Getting this right is what lets us trust backport data
// instead of producing false positives. RPM/EVR is a follow-up (noted).

export type Cmp = -1 | 0 | 1;

function sign(n: number): Cmp {
  return n < 0 ? -1 : n > 0 ? 1 : 0;
}

// --- Debian dpkg comparison -------------------------------------------------

// Order value for a single character per dpkg: '~' before anything (including
// end-of-string), then letters (by ASCII), then everything else (by ASCII,
// shifted above letters so non-letters sort after letters).
function debOrder(ch: string | undefined): number {
  if (ch === undefined) return 0; // end of string
  if (ch === "~") return -1;
  const c = ch.charCodeAt(0);
  const isLetter = (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
  if (isLetter) return c;
  return c + 256; // non-letters sort after letters
}

// Compare the "verrevcmp" way: alternate between non-digit and digit chunks.
function verrevcmp(a: string, b: string): Cmp {
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    // Non-digit prefix, compared by debOrder char-by-char (including '~').
    while (
      (i < a.length && !isDigit(a[i])) ||
      (j < b.length && !isDigit(b[j]))
    ) {
      const oa = debOrder(i < a.length && !isDigit(a[i]) ? a[i] : undefined);
      const ob = debOrder(j < b.length && !isDigit(b[j]) ? b[j] : undefined);
      if (oa !== ob) return sign(oa - ob);
      if (i < a.length && !isDigit(a[i])) i++;
      if (j < b.length && !isDigit(b[j])) j++;
    }

    // Skip leading zeros then compare digit runs numerically.
    while (a[i] === "0") i++;
    while (b[j] === "0") j++;
    let firstDiff = 0;
    while (isDigit(a[i]) && isDigit(b[j])) {
      if (firstDiff === 0) firstDiff = a.charCodeAt(i) - b.charCodeAt(j);
      i++;
      j++;
    }
    if (isDigit(a[i])) return 1; // a has a longer number => larger
    if (isDigit(b[j])) return -1;
    if (firstDiff !== 0) return sign(firstDiff);
  }
  return 0;
}

function isDigit(ch: string | undefined): boolean {
  return ch !== undefined && ch >= "0" && ch <= "9";
}

interface DebParts {
  epoch: number;
  upstream: string;
  revision: string;
}

function parseDeb(v: string): DebParts {
  let epoch = 0;
  let rest = v.trim();
  const colon = rest.indexOf(":");
  if (colon >= 0) {
    const e = Number(rest.slice(0, colon));
    if (Number.isFinite(e)) {
      epoch = e;
      rest = rest.slice(colon + 1);
    }
  }
  let upstream = rest;
  let revision = "";
  const dash = rest.lastIndexOf("-");
  if (dash >= 0) {
    upstream = rest.slice(0, dash);
    revision = rest.slice(dash + 1);
  }
  return { epoch, upstream, revision };
}

export function compareDebian(a: string, b: string): Cmp {
  const pa = parseDeb(a);
  const pb = parseDeb(b);
  if (pa.epoch !== pb.epoch) return sign(pa.epoch - pb.epoch);
  const up = verrevcmp(pa.upstream, pb.upstream);
  if (up !== 0) return up;
  return verrevcmp(pa.revision, pb.revision);
}

// --- General upstream comparison --------------------------------------------

// Tokenize into alternating numeric and non-numeric runs, compare component
// by component: numbers numerically, alpha lexically. A version with an extra
// trailing segment sorts higher ("8.2p1" > "8.2", "1.20.0" > "1.20"), which
// matches how service point/patch releases (OpenSSH p-releases, OpenSSL letter
// releases) actually increment. (Semver pre-release "-rc" semantics are out of
// scope here — service banners don't use them.)
type Token = { num: true; value: number } | { num: false; value: string };

function tokenize(v: string): Token[] {
  const tokens: Token[] = [];
  const re = /(\d+)|([A-Za-z]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(v)) !== null) {
    if (m[1] !== undefined) tokens.push({ num: true, value: Number(m[1]) });
    else tokens.push({ num: false, value: m[2]!.toLowerCase() });
  }
  return tokens;
}

export function compareUpstream(a: string, b: string): Cmp {
  const ta = tokenize(a);
  const tb = tokenize(b);
  const n = Math.max(ta.length, tb.length);
  for (let i = 0; i < n; i++) {
    const x = ta[i];
    const y = tb[i];
    if (x === undefined) return -1; // a ran out => a is smaller
    if (y === undefined) return 1;
    if (x.num && y.num) {
      if (x.value !== y.value) return sign(x.value - y.value);
    } else if (!x.num && !y.num) {
      if (x.value !== y.value) return x.value < y.value ? -1 : 1;
    } else {
      // Mixed: a numeric token outranks an alpha token at the same position
      // ("1.2" > "1.a"). Rare for real service versions.
      return x.num ? 1 : -1;
    }
  }
  return 0;
}
