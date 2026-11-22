# Opens bfd4r-sim's peer session to r2 once its API answers, so the lab
# starts with the session Up. A scenario may change it (bfd: peer).
require 'net/http'
60.times do
  r = Net::HTTP.post(URI('http://127.0.0.1:8080/api/peer'), '{"to":"10.0.24.1"}',
                     'X-BFD4R' => 'routescope', 'Content-Type' => 'application/json')
  break if r.is_a?(Net::HTTPSuccess)
rescue SystemCallError
  nil
ensure
  sleep 1
end
