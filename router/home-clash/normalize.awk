# Keep subscription policy, not its desktop listeners/controllers/TUN settings.
/^[A-Za-z][A-Za-z0-9_-]*:/ {
 key=$0;sub(/:.*/,"",key)
 keep=(key=="proxies" || key=="proxy-groups" || key=="proxy-providers" || key=="rules" || key=="rule-providers" || key=="dns" || key=="hosts" || key=="sniffer")
 if(keep) print
 if(key=="dns") {
  print "  listen: 127.0.0.1:1053"
  print "  enhanced-mode: fake-ip"
  print "  fake-ip-range: 198.19.0.1/16"
 }
 next
}
keep {
 if(key=="dns" && $0~/^  (listen|enhanced-mode|fake-ip-range):/) next
 print
}
