use criterion::{Criterion, criterion_group, criterion_main};
use sentirum_lb::proxy::handler::{CidrRange, client_ip_from_socket_addr, request_id_header_value};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn bench_request_id_header_value(c: &mut Criterion) {
    c.bench_function("request_id_header_value", |b| {
        b.iter(|| {
            let value = request_id_header_value();
            black_box(value);
        })
    });
}

fn bench_client_ip_from_socket_addr(c: &mut Criterion) {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 15)), 8443);
    c.bench_function("client_ip_from_socket_addr", |b| {
        b.iter(|| black_box(client_ip_from_socket_addr(black_box(addr))))
    });
}

fn bench_trusted_proxy_contains(c: &mut Criterion) {
    let cidr = CidrRange::parse("10.42.0.0/16").expect("valid cidr");
    let ip = IpAddr::V4(Ipv4Addr::new(10, 42, 12, 99));
    c.bench_function("trusted_proxy_contains", |b| {
        b.iter(|| black_box(cidr.contains(black_box(&ip))))
    });
}

criterion_group!(
    proxy_hot_path,
    bench_request_id_header_value,
    bench_client_ip_from_socket_addr,
    bench_trusted_proxy_contains
);
criterion_main!(proxy_hot_path);
