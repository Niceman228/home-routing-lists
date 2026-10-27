function emit() {if(host!="" && port~/^[0-9]+$/ && port>0 && port<65536) print host "\t" port}
/^proxies:/ {active=1;next}
/^[A-Za-z][A-Za-z0-9_-]*:/ {if(active){emit();active=0;host="";port=""}}
active && /^  - name:/ {emit();host="";port=""}
active && /^    server:/ {host=$0;sub(/^    server:[ ]*/,"",host);gsub(/["\047\r]/,"",host)}
active && /^    port:/ {port=$0;sub(/^    port:[ ]*/,"",port);gsub(/["\047\r]/,"",port)}
END {if(active) emit()}
