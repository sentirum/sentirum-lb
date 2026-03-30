use crate::route::definition::{RouteCmd, RouteDef};
use std::collections::HashMap;

/// Parse route commands from a string (Fabio-compatible format).
///
/// Supported formats:
/// - `route add <svc> <src> <dst>`
/// - `route add <svc> <src> <dst> weight <w>`
/// - `route add <svc> <src> <dst> tags "<t1>,<t2>"`
/// - `route add <svc> <src> <dst> opts "k1=v1 k2=v2"`
/// - `route add <svc> <src> <dst> weight <w> tags "<t1>,<t2>" opts "k1=v1"`
/// - `route del <svc>`
/// - `route del <svc> <src>`
/// - `route del <svc> <src> <dst>`
/// - `route weight <svc> <src> weight <w>`
///
/// Comments (#, //) and blank lines are ignored.
pub fn parse_route_commands(input: &str) -> Vec<RouteDef> {
    let mut defs = Vec::new();

    for line in input.lines() {
        let line = line.trim();

        // Skip comments and blank lines
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        if let Some(def) = parse_line(line) {
            defs.push(def);
        }
    }

    defs
}

fn parse_line(line: &str) -> Option<RouteDef> {
    let tokens = tokenize(line)?;
    if tokens.is_empty() {
        return None;
    }

    if tokens[0] != "route" || tokens.len() < 3 {
        tracing::warn!("Invalid route command: {}", line);
        return None;
    }

    let cmd = match tokens[1].as_str() {
        "add" => RouteCmd::Add,
        "del" => RouteCmd::Del,
        "weight" => RouteCmd::Weight,
        _ => {
            tracing::warn!("Unknown route command: {}", tokens[1]);
            return None;
        }
    };

    match cmd {
        RouteCmd::Add => parse_route_add(&tokens),
        RouteCmd::Del => parse_route_del(&tokens),
        RouteCmd::Weight => parse_route_weight(&tokens),
    }
}

/// Parse: route add <svc> <src> <dst> [weight <w>] [tags "<t1>,<t2>"] [opts "k1=v1 k2=v2"]
fn parse_route_add(tokens: &[String]) -> Option<RouteDef> {
    if tokens.len() < 5 {
        tracing::warn!("route add requires at least: route add <svc> <src> <dst>");
        return None;
    }

    let service = tokens[2].clone();
    let src = tokens[3].clone();
    let dst = tokens[4].clone();

    let mut weight = 0.0;
    let mut tags = Vec::new();
    let mut opts = HashMap::new();

    let mut i = 5;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "weight" => {
                i += 1;
                if i < tokens.len() {
                    weight = tokens[i].parse().unwrap_or(0.0);
                }
            }
            "tags" => {
                i += 1;
                if i < tokens.len() {
                    tags = tokens[i]
                        .split(',')
                        .map(|t| t.trim().to_string())
                        .filter(|t| !t.is_empty())
                        .collect();
                }
            }
            "opts" => {
                i += 1;
                if i < tokens.len() {
                    for pair in tokens[i].split_whitespace() {
                        if let Some((k, v)) = pair.split_once('=') {
                            opts.insert(k.to_string(), v.to_string());
                        }
                    }
                }
            }
            _ => {
                tracing::warn!("Unknown option in route add: {}", tokens[i]);
            }
        }
        i += 1;
    }

    Some(RouteDef {
        cmd: RouteCmd::Add,
        service,
        src,
        dst,
        weight,
        tags,
        opts,
        source: crate::route::definition::RouteSource::Static,
    })
}

/// Parse: route del <svc> [<src> [<dst>]] or route del <svc> tags "<t1>,<t2>" or route del tags "<t1>,<t2>"
fn parse_route_del(tokens: &[String]) -> Option<RouteDef> {
    let mut service = String::new();
    let mut src = String::new();
    let mut dst = String::new();
    let mut tags = Vec::new();

    let mut i = 2;
    if tokens.get(i).is_some_and(|t| t != "tags") {
        service = tokens[i].clone();
        i += 1;
    }

    while i < tokens.len() {
        match tokens[i].as_str() {
            "tags" => {
                i += 1;
                if i < tokens.len() {
                    tags = tokens[i]
                        .split(',')
                        .map(|t| t.trim().to_string())
                        .filter(|t| !t.is_empty())
                        .collect();
                }
            }
            _ if src.is_empty() => {
                src = tokens[i].clone();
            }
            _ if dst.is_empty() => {
                dst = tokens[i].clone();
            }
            _ => {
                tracing::warn!("Unknown option in route del: {}", tokens[i]);
            }
        }
        i += 1;
    }

    if service.is_empty() && tags.is_empty() {
        tracing::warn!("route del requires either <svc> or tags");
        return None;
    }

    Some(RouteDef {
        cmd: RouteCmd::Del,
        service,
        src,
        dst,
        weight: 0.0,
        tags,
        opts: HashMap::new(),
        source: crate::route::definition::RouteSource::Static,
    })
}

/// Parse: route weight <svc> <src> weight <w> [tags "<t1>,<t2>"] or route weight <src> weight <w> tags "<t1>,<t2>"
fn parse_route_weight(tokens: &[String]) -> Option<RouteDef> {
    let first = tokens.get(2)?.clone();
    let (service, src, mut i) = match tokens.get(3).map(|s| s.as_str()) {
        Some("weight") => (String::new(), first, 3),
        Some(_) => (first, tokens.get(3)?.clone(), 4),
        None => return None,
    };

    let mut weight = 0.0;
    let mut tags = Vec::new();
    while i < tokens.len() {
        match tokens[i].as_str() {
            "weight" => {
                i += 1;
                if i < tokens.len() {
                    weight = tokens[i].parse().unwrap_or(0.0);
                }
            }
            "tags" => {
                i += 1;
                if i < tokens.len() {
                    tags = tokens[i]
                        .split(',')
                        .map(|t| t.trim().to_string())
                        .filter(|t| !t.is_empty())
                        .collect();
                }
            }
            _ => {}
        }
        i += 1;
    }

    Some(RouteDef {
        cmd: RouteCmd::Weight,
        service,
        src,
        dst: String::new(),
        weight,
        tags,
        opts: HashMap::new(),
        source: crate::route::definition::RouteSource::Static,
    })
}

/// Tokenize a route command line, respecting quoted strings.
fn tokenize(line: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let chars = line.chars().peekable();

    for c in chars {
        match c {
            '"' => {
                in_quotes = !in_quotes;
            }
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    Some(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_route_add_simple() {
        let input = "route add myservice myhost.com/ http://10.0.0.1:8080/";
        let defs = parse_route_commands(input);
        assert_eq!(defs.len(), 1);
        let d = &defs[0];
        assert!(matches!(d.cmd, RouteCmd::Add));
        assert_eq!(d.service, "myservice");
        assert_eq!(d.src, "myhost.com/");
        assert_eq!(d.dst, "http://10.0.0.1:8080/");
    }

    #[test]
    fn test_parse_route_add_with_weight() {
        let input = "route add myservice myhost.com/ http://10.0.0.1:8080/ weight 0.5";
        let defs = parse_route_commands(input);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].weight, 0.5);
    }

    #[test]
    fn test_parse_route_add_with_tags() {
        let input = r#"route add myservice myhost.com/ http://10.0.0.1:8080/ tags "v1,canary""#;
        let defs = parse_route_commands(input);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].tags, vec!["v1", "canary"]);
    }

    #[test]
    fn test_parse_route_add_with_opts() {
        let input = r#"route add myservice myhost.com/ http://10.0.0.1:8080/ opts "strip=/api prepend=/v2""#;
        let defs = parse_route_commands(input);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].opts.get("strip"), Some(&"/api".to_string()));
        assert_eq!(defs[0].opts.get("prepend"), Some(&"/v2".to_string()));
    }

    #[test]
    fn test_parse_route_add_full() {
        let input = r#"route add myservice myhost.com/api/ http://10.0.0.1:8080/ weight 0.7 tags "v1" opts "strip=/api tlsskipverify=true""#;
        let defs = parse_route_commands(input);
        assert_eq!(defs.len(), 1);
        let d = &defs[0];
        assert_eq!(d.weight, 0.7);
        assert_eq!(d.tags, vec!["v1"]);
        assert_eq!(d.opts.get("strip"), Some(&"/api".to_string()));
    }

    #[test]
    fn test_parse_route_del() {
        let input = "route del myservice";
        let defs = parse_route_commands(input);
        assert_eq!(defs.len(), 1);
        assert!(matches!(defs[0].cmd, RouteCmd::Del));
        assert_eq!(defs[0].service, "myservice");
    }

    #[test]
    fn test_parse_route_del_with_tags_only() {
        let input = r#"route del myservice tags "v1,canary""#;
        let defs = parse_route_commands(input);
        assert_eq!(defs.len(), 1);
        assert!(defs[0].src.is_empty());
        assert!(defs[0].dst.is_empty());
        assert_eq!(defs[0].tags, vec!["v1", "canary"]);
    }

    #[test]
    fn test_parse_route_del_global_tags() {
        let input = r#"route del tags "v1,canary""#;
        let defs = parse_route_commands(input);
        assert_eq!(defs.len(), 1);
        assert!(defs[0].service.is_empty());
        assert_eq!(defs[0].tags, vec!["v1", "canary"]);
    }

    #[test]
    fn test_parse_route_weight_with_tags() {
        let input = r#"route weight myservice myhost.com/api/ weight 0.5 tags "v1,canary""#;
        let defs = parse_route_commands(input);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].weight, 0.5);
        assert_eq!(defs[0].tags, vec!["v1", "canary"]);
    }

    #[test]
    fn test_parse_route_weight_without_service_with_tags() {
        let input = r#"route weight myhost.com/api/ weight 0.5 tags "v1,canary""#;
        let defs = parse_route_commands(input);
        assert_eq!(defs.len(), 1);
        assert!(defs[0].service.is_empty());
        assert_eq!(defs[0].src, "myhost.com/api/");
        assert_eq!(defs[0].weight, 0.5);
        assert_eq!(defs[0].tags, vec!["v1", "canary"]);
    }

    #[test]
    fn test_parse_comments_and_blanks() {
        let input = r#"
# This is a comment
// Another comment

route add svc host/ http://backend/

# Another comment after
"#;
        let defs = parse_route_commands(input);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].service, "svc");
    }

    #[test]
    fn test_parse_multiple_routes() {
        let input = r#"
route add svc1 host1/ http://10.0.0.1:8080/
route add svc1 host1/ http://10.0.0.2:8080/
route add svc2 host2/ http://10.0.0.3:9090/
"#;
        let defs = parse_route_commands(input);
        assert_eq!(defs.len(), 3);
    }

    #[test]
    fn test_src_host_and_path() {
        let input = "route add svc myhost.com/api/v2/ http://backend/";
        let defs = parse_route_commands(input);
        let d = &defs[0];
        assert_eq!(d.src_host(), "myhost.com");
        assert_eq!(d.src_path(), "api/v2/");
    }
}
