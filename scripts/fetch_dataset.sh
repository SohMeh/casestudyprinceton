#!/usr/bin/env bash
# Downloads the NIST CFReDS Data Leakage Case into ./data (resumable).
# Usage: bash scripts/fetch_dataset.sh            small images + answer key + PC image (E01, 7.3 GB)
#        bash scripts/fetch_dataset.sh --small    small images + answer key only (about 410 MB)
#        bash scripts/fetch_dataset.sh --pc7z     PC image as the 5 GB 7z set instead of E01
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
DATA="${CASE_REPLAY_DATA:-$HERE/data}"
BASE="https://cfreds-archive.nist.gov/data_leakage_case"
MODE="${1:-full}"
mkdir -p "$DATA"

get() {  # url, output name, expected sha1
  local url="$1" out="$DATA/$2" want="$3"
  echo ""
  echo "==> $2"
  curl -L --fail --retry 5 --retry-delay 3 -C - -o "$out" "$url" || { echo "   download failed: $url"; return 1; }
  if [ -n "$want" ]; then
    local got
    got="$(shasum -a 1 "$out" | awk '{print toupper($1)}')"
    if [ "$got" = "$want" ]; then echo "   sha1 ok"; else echo "   sha1 MISMATCH (got $got, NIST lists $want)"; fi
  fi
}

# Small files first so work can start right away.
get "$BASE/images/rm%231/cfreds_2015_data_leakage_rm%231.E01"        "rm1.E01"        "FFD0F3CBA3DFE3291F786B845A06A8AA56C1CD8C"
get "$BASE/images/rm%232/cfreds_2015_data_leakage_rm%232.E01"        "rm2.E01"        "2228554CD6FDD3C85BB80E0A0CD7F21A2364DC99"
get "$BASE/images/rm%233/cfreds_2015_data_leakage_rm%233_type3.E01"  "rm3_type3.E01"  "75C106FDB2FD2F8068190E951589FF1F9860257E"
get "$BASE/leakage-answers.pdf"                                      "leakage-answers.pdf" ""
touch "$DATA/.small_done"

if [ "$MODE" = "--small" ]; then echo ""; echo "Small set done: $DATA"; exit 0; fi

if [ "$MODE" = "--pc7z" ]; then
  get "$BASE/images/pc/cfreds_2015_data_leakage_pc.7z.001" "cfreds_2015_data_leakage_pc.7z.001" "F07632FAA66A47088DEB07BDB45CC568E4BF650B"
  get "$BASE/images/pc/cfreds_2015_data_leakage_pc.7z.002" "cfreds_2015_data_leakage_pc.7z.002" "5DEE46ABF6FA833268E5AE199A13854CCF42689B"
  get "$BASE/images/pc/cfreds_2015_data_leakage_pc.7z.003" "cfreds_2015_data_leakage_pc.7z.003" "1687686F819092E05047F195F102D8FA0C38ED66"
else
  get "$BASE/images/pc/cfreds_2015_data_leakage_pc.E01" "cfreds_2015_data_leakage_pc.E01" "72432916933F5A309A8C456B40C9601D1F8D2A4F"
  get "$BASE/images/pc/cfreds_2015_data_leakage_pc.E02" "cfreds_2015_data_leakage_pc.E02" "0CAF4261ED8432A8B3BAA019B1B28FDF96F79130"
  get "$BASE/images/pc/cfreds_2015_data_leakage_pc.E03" "cfreds_2015_data_leakage_pc.E03" "BE836C891736C4C0C2253C6803399BF0F2A599BA"
  get "$BASE/images/pc/cfreds_2015_data_leakage_pc.E04" "cfreds_2015_data_leakage_pc.E04" "9159BFFD56097495F73FBBF967B75EB288B1E3DE"
fi
touch "$DATA/.pc_done"
echo ""
echo "All done: $DATA"
