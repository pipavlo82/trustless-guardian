FROM scratch
COPY --chmod=0555 worker /worker
USER 65534:65534
ENTRYPOINT ["/worker"]
