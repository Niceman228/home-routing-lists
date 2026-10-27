#!/bin/sh
set -eu
umask 077
B=/etc/home-clash
R=/tmp/home-clash
awk -f "$B/servers.awk" "$B/private/source.yaml" > "$R/servers.tsv"
[ -s "$R/servers.tsv" ] || exit 1
: > "$R/endpoints.new"
while IFS="$(printf '\t')" read -r host port;do
 case "$host" in ''|*[!a-zA-Z0-9.-]*) continue;; esac
 case "$port" in ''|*[!0-9]*) continue;; esac
 case "$host" in *[!0-9.]*) dig +short +timeout=2 +tries=1 A "$host" @1.1.1.1 > "$R/addresses" 2>/dev/null || true;; *) printf '%s\n' "$host" > "$R/addresses";;esac
 awk -F. 'NF==4 {ok=1;for(i=1;i<=4;i++)if($i!~/^[0-9]+$/||$i>255)ok=0;if(ok)print}' "$R/addresses" |
 while IFS= read -r ip;do printf '%s . %s\n' "$ip" "$port";done >> "$R/endpoints.new"
done < "$R/servers.tsv"
[ ! -f "$B/endpoints.txt" ] || cat "$B/endpoints.txt" >> "$R/endpoints.new"
sort -u "$R/endpoints.new" > "$R/endpoints.sorted"
[ -s "$R/endpoints.sorted" ] || exit 1
[ "$(wc -l < "$R/endpoints.sorted")" -le 512 ] || exit 1
entries=$(awk 'BEGIN{s=""}{printf "%s%s",s,$0;s=", "}' "$R/endpoints.sorted")
awk -v entries="$entries" '/elements =/ {$0="        elements = { " entries " }"} {print}' /etc/home-routing/vpn-outer.nft > "$R/outer.nft"
{ echo 'delete table inet home_vpn_dpi_candidate';cat "$R/outer.nft"; } > "$R/outer.apply"
nft -c -f "$R/outer.apply"
nft -f "$R/outer.apply"
cp "$R/outer.nft" /etc/home-routing/vpn-outer.nft
cp "$R/endpoints.sorted" "$B/endpoints.txt"
