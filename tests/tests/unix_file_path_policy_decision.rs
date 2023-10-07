#[cfg(unix)]
#[test]
fn file_path_policy_decision() {
    use iris_policy::{Policy, PolicyVerdict, os::PolicyRequest};
    use libc::{O_RDONLY, O_RDWR, O_WRONLY};

    let mut policy = Policy::nothing_allowed();
    policy.allow_file_read("/etc/hosts").unwrap();
    println!("{:?}", &policy);
    assert_eq!(
        policy.evaluate_request(&PolicyRequest::FileOpen {
            path: "/etc/hosts",
            flags: O_RDONLY
        }),
        PolicyVerdict::Granted,
        "exact file path did not match"
    );
    assert!(
        matches!(
            policy.evaluate_request(&PolicyRequest::FileOpen {
                path: "/etc/nothosts",
                flags: O_RDONLY
            }),
            PolicyVerdict::DeniedByPolicy { .. }
        ),
        "different file path should not have matched"
    );
    assert!(
        matches!(
            policy.evaluate_request(&PolicyRequest::FileOpen {
                path: "/etc/hosts",
                flags: O_WRONLY
            }),
            PolicyVerdict::DeniedByPolicy { .. }
        ),
        "different file rights should not have matched"
    );
    assert!(
        matches!(
            policy.evaluate_request(&PolicyRequest::FileOpen {
                path: "/etc/hosts ",
                flags: O_RDONLY
            }),
            PolicyVerdict::DeniedByPolicy { .. }
        ),
        "trailing spaces should not be canonicalized"
    );

    let mut policy = Policy::nothing_allowed();
    policy.allow_dir_write("/without_trailing_slash").unwrap();
    println!("{:?}", &policy);
    assert_eq!(
        policy.evaluate_request(&PolicyRequest::FileOpen {
            path: "/without_trailing_slash",
            flags: O_WRONLY
        }),
        PolicyVerdict::Granted,
        "exact dir path did not match"
    );
    assert_eq!(
        policy.evaluate_request(&PolicyRequest::FileOpen {
            path: "/without_trailing_slash/",
            flags: O_WRONLY
        }),
        PolicyVerdict::Granted,
        "exact dir path did not match with a trailing slash"
    );
    assert!(
        matches!(
            policy.evaluate_request(&PolicyRequest::FileOpen {
                path: "/not_without_trailing_slash",
                flags: O_WRONLY
            }),
            PolicyVerdict::DeniedByPolicy { .. }
        ),
        "different dir path should not have matched"
    );
    assert!(
        matches!(
            policy.evaluate_request(&PolicyRequest::FileOpen {
                path: "/without_trailing_slash",
                flags: O_RDONLY
            }),
            PolicyVerdict::DeniedByPolicy { .. }
        ),
        "different dir rights should not have matched"
    );

    let mut policy = Policy::nothing_allowed();
    policy.allow_dir_read("/etc/").unwrap();
    assert_eq!(
        policy.evaluate_request(&PolicyRequest::FileOpen {
            path: "/etc/hosts",
            flags: O_RDONLY
        }),
        PolicyVerdict::Granted,
        "direct directory child did not match"
    );
    assert_eq!(
        policy.evaluate_request(&PolicyRequest::FileOpen {
            path: "/etc/ssh/ssh_config",
            flags: O_RDONLY
        }),
        PolicyVerdict::Granted,
        "directory sub-child did not match"
    );

    let mut policy = Policy::nothing_allowed();
    policy.allow_dir_read("/home/me/").unwrap();
    policy.allow_dir_write("/home/me/.cache/").unwrap();
    assert_eq!(
        policy.evaluate_request(&PolicyRequest::FileOpen {
            path: "/home/me/.cache/a.txt",
            flags: O_RDWR
        }),
        PolicyVerdict::Granted,
        "access rights from different rules should have been combined together"
    );

    let mut policy = Policy::nothing_allowed();
    policy.allow_dir_read("/home/me/").unwrap();
    assert!(
        matches!(
            policy.evaluate_request(&PolicyRequest::FileOpen {
                path: "a.txt",
                flags: O_RDONLY
            }),
            PolicyVerdict::InvalidRequestParameters { .. }
        ),
        "relative paths should be denied"
    );
    assert!(
        matches!(
            policy.evaluate_request(&PolicyRequest::FileOpen {
                path: "../../../../../../../../home/me/a.txt",
                flags: O_RDONLY
            }),
            PolicyVerdict::InvalidRequestParameters { .. }
        ),
        "relative paths should be denied"
    );
    assert!(
        matches!(
            policy.evaluate_request(&PolicyRequest::FileOpen {
                path: "/home/me/../a.txt",
                flags: O_RDONLY
            }),
            PolicyVerdict::InvalidRequestParameters { .. }
        ),
        "unresolved ../ in paths should be denied"
    );
    assert!(
        matches!(
            policy.evaluate_request(&PolicyRequest::FileOpen {
                path: "/home/me/./a.txt",
                flags: O_RDONLY
            }),
            PolicyVerdict::InvalidRequestParameters { .. }
        ),
        "unresolved ../ in paths should be denied"
    );
}
