# Runs after the previous policy generator. Its local interception/adblock stay.
.outbounds = ([.outbounds[]|select(.tag!="subscription-out")] + [
 {type:"socks",tag:"subscription-out",server:"127.0.0.1",server_port:11082,version:"5"}
]) |
.dns.servers |= map(if .tag=="dns-server" then
 {type:"udp",tag:"dns-server",server:"127.0.0.1",server_port:1053}
 elif .type=="fakeip" then .inet4_range="198.18.0.0/16" else . end) |
.route.rules |= map(if .action=="route" and .inbound=="tproxy-in" then .outbound="subscription-out" else . end) |
.route.final="subscription-out"
