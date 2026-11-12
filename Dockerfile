# isis4r as a router in a container: isisd, isis-cli, and Ruby for the
# one-line API client routescope runs here.
#
#   docker build -t isis4r --build-context datalink-socket=../datalink-socket .
#   docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \
#     -v $PWD/isisd.yml:/etc/isis4r/isisd.yml isis4r
#
# datalink-socket is a sibling checkout, handed in as a named build
# context, since the gem is not published.

ARG RUBY_VERSION=3.3
FROM ruby:${RUBY_VERSION}-slim AS base

LABEL org.opencontainers.image.title="isis4r" \
      org.opencontainers.image.description="A programmable IS-IS router and protocol testing platform" \
      org.opencontainers.image.source="https://github.com/jeanmichel-gh/isis" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

WORKDIR /app
COPY --from=datalink-socket lib/ /datalink-socket/lib/
COPY lib/ lib/
COPY exe/ exe/
COPY docs/ docs/
COPY isis4r.gemspec LICENSE.txt ./
ENV PATH=/app/exe:$PATH \
    RUBYLIB=/app/lib:/datalink-socket/lib \
    RUBYOPT=--disable-did_you_mean

# ---- tests: docker build --target test ...
FROM base AS test
RUN gem install --no-document minitest -v '~> 5.0'
COPY test/ test/
# test/scenario/isis4r_areas_lab_test.rb runs an example lab's own files.
COPY examples/ examples/
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
ENTRYPOINT ["isisd"]
CMD ["-c", "/etc/isis4r/isisd.yml", "-l", "-"]

# Passive capture helper: same protocol parser, no daemon startup.
FROM runtime AS capture
ENTRYPOINT ["isis-capture"]
CMD ["-i", "eth0"]

FROM runtime AS router
