# isis4r as a router in a container: isisd, isis-cli, and Ruby for the
# one-line API client routescope runs here; and bfdd4r beside isisd, for
# interfaces with bfd: true (with-bfdd4r, the entrypoint).
#
#   docker build -t isis4r --build-context datalink-socket=../datalink-socket --build-context bfd4r=../bfd4r .
#   docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \
#     -v $PWD/isisd.yml:/etc/isis4r/isisd.yml isis4r
#
# datalink-socket and bfd4r are sibling checkouts, handed in as named build
# contexts, since the gems are not published. bfd4r's require path is its
# root, so its bfd/, bfd4r.rb and exe/ are copied.

ARG RUBY_VERSION=3.3
FROM ruby:${RUBY_VERSION}-slim AS base

LABEL org.opencontainers.image.title="isis4r" \
      org.opencontainers.image.description="A programmable IS-IS router and protocol testing platform" \
      org.opencontainers.image.source="https://github.com/jeanmichel-gh/isis" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

WORKDIR /app
COPY --from=datalink-socket lib/ /datalink-socket/lib/
COPY --from=bfd4r bfd/ /bfd4r/bfd/
COPY --from=bfd4r bfd4r.rb /bfd4r/
COPY --from=bfd4r exe/ /bfd4r/exe/
COPY lib/ lib/
COPY exe/ exe/
COPY docs/ docs/
COPY isis4r.gemspec LICENSE.txt ./
ENV PATH=/app/exe:/bfd4r/exe:$PATH \
    RUBYLIB=/app/lib:/datalink-socket/lib:/bfd4r \
    RUBYOPT=--disable-did_you_mean

# ---- tests: docker build --target test ...
FROM base AS test
RUN gem install --no-document minitest -v '~> 5.0'
COPY test/ test/
# test/scenario/isis4r_areas_lab_test.rb runs an example lab's own files.
COPY routescope/labs/ routescope/labs/
RUN ruby -Ilib -Itest -e 'Dir["test/{unit,docs,scenario}/**/*_test.rb"].sort.each { |f| require "./#{f}" }'

# ---- runtime
FROM base AS runtime
# Opening the interfaces needs CAP_NET_RAW, installing routes NET_ADMIN,
# granted at run time. iproute2 to look at what it installed: proto 187.
# ping, from iputils-ping, to check that packets follow those routes, as
# a lab's scenarios do with routescope's ping condition.
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends iproute2 tcpdump iputils-ping \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /etc/iproute2/rt_protos.d /etc/isis4r /run/isis4r \
 && echo '187 isis' > /etc/iproute2/rt_protos.d/isis4r.conf
# with-bfdd4r starts bfdd4r in the background, again a second after it
# fails, and then runs isisd in its place (bfd4r exe/with-bfdd4r). A lab
# that sets its own entrypoint and wants BFD puts with-bfdd4r first.
ENTRYPOINT ["with-bfdd4r", "isisd"]
CMD ["-c", "/etc/isis4r/isisd.yml", "-l", "-"]

# Passive capture helper: same protocol parser, no daemon startup.
FROM runtime AS capture
ENTRYPOINT ["isis-capture"]
CMD ["-i", "eth0"]

FROM runtime AS router
