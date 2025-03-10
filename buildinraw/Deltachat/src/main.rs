/// The available configuration keys.
/*
extern crate strum;
#[macro_use]
extern crate strum_macros;
// */


use strum::{EnumProperty, IntoEnumIterator};
use strum_macros::{AsRefStr, Display, EnumIter, EnumString};

use serde_json;
use serde::{Deserialize, Serialize};

//use str::to_lowercase;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Display,
    EnumString,
    AsRefStr,
    EnumIter,
    EnumProperty,
    PartialOrd,
    Ord,
    Serialize,
)]
#[strum(serialize_all = "snake_case")]
pub enum Config {
    /// Email address, used in the `From:` field.
    Addr,

    /// IMAP server hostname.
    MailServer,

    /// IMAP server username.
    MailUser,

    /// IMAP server password.
    MailPw,

    /// IMAP server port.
    MailPort,

    /// IMAP server security (e.g. TLS, STARTTLS).
    MailSecurity,

    /// How to check IMAP server TLS certificates.
    ImapCertificateChecks,

    /// SMTP server hostname.
    SendServer,

    /// SMTP server username.
    SendUser,

    /// SMTP server password.
    SendPw,

    /// SMTP server port.
    SendPort,

    /// SMTP server security (e.g. TLS, STARTTLS).
    SendSecurity,

    /// How to check SMTP server TLS certificates.
    SmtpCertificateChecks,

    /// Whether to use OAuth 2.
    ///
    /// Historically contained other bitflags, which are now deprecated.
    /// Should not be extended in the future, create new config keys instead.
    ServerFlags,

    /// True if SOCKS5 is enabled.
    ///
    /// Can be used to disable SOCKS5 without erasing SOCKS5 configuration.
    Socks5Enabled,

    /// SOCKS5 proxy server hostname or address.
    Socks5Host,

    /// SOCKS5 proxy server port.
    Socks5Port,

    /// SOCKS5 proxy server username.
    Socks5User,

    /// SOCKS5 proxy server password.
    Socks5Password,

    /// Own name to use in the `From:` field when sending messages.
    Displayname,

    /// Own status to display, sent in message footer.
    Selfstatus,

    /// Own avatar filename.
    Selfavatar,

    /// Send BCC copy to self.
    ///
    /// Should be enabled for multidevice setups.
    #[strum(props(default = "1"))]
    BccSelf,

    /// True if encryption is preferred according to Autocrypt standard.
    #[strum(props(default = "1"))]
    E2eeEnabled,

    /// True if Message Delivery Notifications (read receipts) should
    /// be sent and requested.
    #[strum(props(default = "1"))]
    MdnsEnabled,

    /// True if "Sent" folder should be watched for changes.
    #[strum(props(default = "0"))]
    SentboxWatch,

    /// True if chat messages should be moved to a separate folder.
    #[strum(props(default = "1"))]
    MvboxMove,

    /// Watch for new messages in the "Mvbox" (aka DeltaChat folder) only.
    ///
    /// This will not entirely disable other folders, e.g. the spam folder will also still
    /// be watched for new messages.
    #[strum(props(default = "0"))]
    OnlyFetchMvbox,

    /// Whether to show classic emails or only chat messages.
    #[strum(props(default = "2"))] // also change ShowEmails.default() on changes
    ShowEmails,

    /// Quality of the media files to send.
    #[strum(props(default = "0"))] // also change MediaQuality.default() on changes
    MediaQuality,

    /// If set to "1", on the first time `start_io()` is called after configuring,
    /// the newest existing messages are fetched.
    /// Existing recipients are added to the contact database regardless of this setting.
    #[strum(props(default = "0"))]
    FetchExistingMsgs,

    /// If set to "1", then existing messages are considered to be already fetched.
    /// This flag is reset after successful configuration.
    #[strum(props(default = "1"))]
    FetchedExistingMsgs,

    /// Type of the OpenPGP key to generate.
    #[strum(props(default = "0"))]
    KeyGenType,

    /// Timer in seconds after which the message is deleted from the
    /// server.
    ///
    /// Equals to 0 by default, which means the message is never
    /// deleted.
    ///
    /// Value 1 is treated as "delete at once": messages are deleted
    /// immediately, without moving to DeltaChat folder.
    #[strum(props(default = "0"))]
    DeleteServerAfter,

    /// Timer in seconds after which the message is deleted from the
    /// device.
    ///
    /// Equals to 0 by default, which means the message is never
    /// deleted.
    #[strum(props(default = "0"))]
    DeleteDeviceAfter,

    /// Move messages to the Trash folder instead of marking them "\Deleted". Overrides
    /// `ProviderOptions::delete_to_trash`.
    DeleteToTrash,

    /// Save raw MIME messages with headers in the database if true.
    SaveMimeHeaders,

    /// The primary email address. Also see `SecondaryAddrs`.
    ConfiguredAddr,

    /// Configured IMAP server hostname.
    ConfiguredMailServer,

    /// Configured IMAP server username.
    ConfiguredMailUser,

    /// Configured IMAP server password.
    ConfiguredMailPw,

    /// Configured IMAP server port.
    ConfiguredMailPort,

    /// Configured IMAP server security (e.g. TLS, STARTTLS).
    ConfiguredMailSecurity,

    /// How to check IMAP server TLS certificates.
    ConfiguredImapCertificateChecks,

    /// Configured SMTP server hostname.
    ConfiguredSendServer,

    /// Configured SMTP server username.
    ConfiguredSendUser,

    /// Configured SMTP server password.
    ConfiguredSendPw,

    /// Configured SMTP server port.
    ConfiguredSendPort,

    /// How to check SMTP server TLS certificates.
    ConfiguredSmtpCertificateChecks,

    /// Whether OAuth 2 is used with configured provider.
    ConfiguredServerFlags,

    /// Configured SMTP server security (e.g. TLS, STARTTLS).
    ConfiguredSendSecurity,

    /// Configured folder for incoming messages.
    ConfiguredInboxFolder,

    /// Configured folder for chat messages.
    ConfiguredMvboxFolder,

    /// Configured "Sent" folder.
    ConfiguredSentboxFolder,

    /// Configured "Trash" folder.
    ConfiguredTrashFolder,

    /// Unix timestamp of the last successful configuration.
    ConfiguredTimestamp,

    /// ID of the configured provider from the provider database.
    ConfiguredProvider,

    /// True if account is configured.
    Configured,

    /// All secondary self addresses separated by spaces
    /// (`addr1@example.org addr2@example.org addr3@example.org`)
    SecondaryAddrs,

    /// Read-only core version string.
    #[strum(serialize = "sys.version")]
    SysVersion,

    /// Maximal recommended attachment size in bytes.
    #[strum(serialize = "sys.msgsize_max_recommended")]
    SysMsgsizeMaxRecommended,

    /// Space separated list of all config keys available.
    #[strum(serialize = "sys.config_keys")]
    SysConfigKeys,

    /// True if it is a bot account.
    Bot,

    /// True when to skip initial start messages in groups.
    #[strum(props(default = "0"))]
    SkipStartMessages,

    /// Whether we send a warning if the password is wrong (set to false when we send a warning
    /// because we do not want to send a second warning)
    #[strum(props(default = "0"))]
    NotifyAboutWrongPw,

    /// If a warning about exceeding quota was shown recently,
    /// this is the percentage of quota at the time the warning was given.
    /// Unset, when quota falls below minimal warning threshold again.
    QuotaExceeding,

    /// address to webrtc instance to use for videochats
    WebrtcInstance,

    /// Timestamp of the last time housekeeping was run
    LastHousekeeping,

    /// Timestamp of the last `CantDecryptOutgoingMsgs` notification.
    LastCantDecryptOutgoingMsgs,

    /// To how many seconds to debounce scan_all_folders. Used mainly in tests, to disable debouncing completely.
    #[strum(props(default = "60"))]
    ScanAllFoldersDebounceSecs,

    /// Whether to avoid using IMAP IDLE even if the server supports it.
    ///
    /// This is a developer option for testing "fake idle".
    #[strum(props(default = "0"))]
    DisableIdle,

    /// Defines the max. size (in bytes) of messages downloaded automatically.
    /// 0 = no limit.
    #[strum(props(default = "0"))]
    DownloadLimit,

    /// Enable sending and executing (applying) sync messages. Sending requires `BccSelf` to be set.
    #[strum(props(default = "1"))]
    SyncMsgs,

    /// Space-separated list of all the authserv-ids which we believe
    /// may be the one of our email server.
    ///
    /// See `crate::authres::update_authservid_candidates`.
    AuthservIdCandidates,

    /// Make all outgoing messages with Autocrypt header "multipart/signed".
    SignUnencrypted,

    /// Let the core save all events to the database.
    /// This value is used internally to remember the MsgId of the logging xdc
    #[strum(props(default = "0"))]
    DebugLogging,

    /// Last message processed by the bot.
    LastMsgId,

    /// How often to gossip Autocrypt keys in chats with multiple recipients, in seconds. 2 days by
    /// default.
    ///
    /// This is not supposed to be changed by UIs and only used for testing.
    #[strum(props(default = "172800"))]
    GossipPeriod,

    /// Feature flag for verified 1:1 chats; the UI should set it
    /// to 1 if it supports verified 1:1 chats.
    /// Regardless of this setting, `chat.is_protected()` returns true while the key is verified,
    /// and when the key changes, an info message is posted into the chat.
    /// 0=Nothing else happens when the key changes.
    /// 1=After the key changed, `can_send()` returns false and `is_protection_broken()` returns true
    /// until `chat_id.accept()` is called.
    #[strum(props(default = "0"))]
    VerifiedOneOnOneChats,

    /// Row ID of the key in the `keypairs` table
    /// used for signatures, encryption to self and included in `Autocrypt` header.
    KeyId,

    /// This key is sent to the self_reporting bot so that the bot can recognize the user
    /// without storing the email address
    SelfReportingId,
}

#[derive(Debug, Serialize)]
pub enum Status {
    /// Provider is known to be working with Delta Chat.
    Ok = 1,

    /// Provider works with Delta Chat, but requires some preparation,
    /// such as changing the settings in the web interface.
    Preparation = 2,

    /// Provider is known not to work with Delta Chat.
    Broken = 3,
}

#[derive(Debug, Serialize, Copy, Clone, PartialEq)]
pub enum Protocol {
    /// SMTP protocol.
    Smtp = 1,

    /// IMAP protocol.
    Imap = 2,
}

#[derive(Debug, Default, Serialize, Copy, Clone)]
pub enum Socket {
    /// Unspecified socket security, select automatically.
    #[default]
    Automatic = 0,

    /// TLS connection.
    Ssl = 1,

    /// STARTTLS connection.
    Starttls = 2,

    /// No TLS, plaintext connection.
    Plain = 3,
}

#[derive(Debug, Serialize, Copy, Clone)]
pub enum UsernamePattern {
    /// Whole email is used as username.
    Email = 1,

    /// Part of address before `@` is used as username.
    Emaillocalpart = 2,
}

#[derive(Debug, Serialize)]
pub enum Oauth2Authorizer {
    /// Yandex.
    Yandex = 1,

    /// Gmail.
    Gmail = 2,
}

#[derive(Debug, Serialize, Copy, Clone)]
pub struct Server {
    /// Server protocol, e.g. SMTP or IMAP.
    pub protocol: Protocol,

    /// Port security, e.g. TLS or STARTTLS.
    pub socket: Socket,

    /// Server host.
    pub hostname: &'static str,

    /// Server port.
    pub port: u16,

    /// Pattern used to construct login usernames from email addresses.
    pub username_pattern: UsernamePattern,
}

#[derive(Debug, Serialize)]
pub struct ConfigDefault {
    /// Configuration variable name.
    pub key: Config,

    /// Configuration variable value.
    pub value: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Provider {
    /// Unique ID, corresponding to provider database filename.
    pub id: &'static str,

    /// Provider status according to manual testing.
    pub status: Status,

    /// Hint to be shown to the user on the login screen.
    pub before_login_hint: &'static str,

    /// Hint to be added to the device chat after provider configuration.
    pub after_login_hint: &'static str,

    /// URL of the page with provider overview.
    pub overview_page: &'static str,

    /// List of provider servers.
    pub server: &'static [Server],

    /// Default configuration values to set when provider is configured.
    pub config_defaults: Option<&'static [ConfigDefault]>,

    /// Type of OAuth 2 authorization if provider supports it.
    pub oauth2_authorizer: Option<Oauth2Authorizer>,

    /// Options with good defaults.
    pub opt: ProviderOptions,
}

#[derive(Debug, Serialize)]
pub struct ProviderOptions {
    /// True if provider is known to use use proper,
    /// not self-signed certificates.
    pub strict_tls: bool,

    /// Maximum number of recipients the provider allows to send a single email to.
    pub max_smtp_rcpt_to: Option<u16>,

    /// Move messages to the Trash folder instead of marking them "\Deleted".
    pub delete_to_trash: bool,
}


impl ProviderOptions {
    const fn new() -> Self {
        Self {
            strict_tls: true,
            max_smtp_rcpt_to: None,
            delete_to_trash: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Moserver {
    /// Server protocol, e.g. SMTP or IMAP.
    pub r#type: Protocol,
    
    /// Server host.
    pub hostname: &'static str,
    
    /// Server port.
    pub port: String,

    /// Port security, e.g. TLS or STARTTLS.
    pub socketType: Socket,

    /// login authentication.
    pub authentication: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Autoconfig {
    /// List of provider incomeservers.
    pub incomingServers: Vec<Moserver>,
    
    /// List of provider outgoservers.
    pub outgoingServers: Vec<Moserver>,
}

#[derive(Debug, Serialize)]
pub struct Result {
    /// Unique ID, corresponding to provider database filename.
    pub domain: &'static str,
    
    pub DeltaChat: Autoconfig,
}

use Protocol::*;
use Socket::*;
use UsernamePattern::*;


// 163.md: 163.com
static P_163: Provider = Provider {
    id: "163",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/163",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "imap.163.com",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "smtp.163.com",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// aktivix.org.md: aktivix.org
static P_AKTIVIX_ORG: Provider = Provider {
    id: "aktivix.org",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/aktivix-org",
    server: &[
        Server {
            protocol: Imap,
            socket: Starttls,
            hostname: "newyear.aktivix.org",
            port: 143,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Starttls,
            hostname: "newyear.aktivix.org",
            port: 587,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// aol.md: aol.com
static P_AOL: Provider = Provider {
    id: "aol",
    status: Status::Preparation,
    before_login_hint: "To log in to AOL with Delta Chat, you need to set up an app password in the AOL web interface.",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/aol",
    server: &[
        Server { protocol: Imap, socket: Ssl, hostname: "imap.aol.com", port: 993, username_pattern: Email },
        Server { protocol: Smtp, socket: Ssl, hostname: "smtp.aol.com", port: 465, username_pattern: Email },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// arcor.de.md: arcor.de
static P_ARCOR_DE: Provider = Provider {
    id: "arcor.de",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/arcor-de",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "imap.arcor.de",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "mail.arcor.de",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// autistici.org.md: autistici.org
static P_AUTISTICI_ORG: Provider = Provider {
    id: "autistici.org",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/autistici-org",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "mail.autistici.org",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "smtp.autistici.org",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// blindzeln.org.md: delta.blinzeln.de, delta.blindzeln.org
static P_BLINDZELN_ORG: Provider = Provider {
    id: "blindzeln.org",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/blindzeln-org",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "webbox222.server-home.org",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "webbox222.server-home.org",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// bluewin.ch.md: bluewin.ch
static P_BLUEWIN_CH: Provider = Provider {
    id: "bluewin.ch",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/bluewin-ch",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "imaps.bluewin.ch",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "smtpauths.bluewin.ch",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// buzon.uy.md: buzon.uy
static P_BUZON_UY: Provider = Provider {
    id: "buzon.uy",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/buzon-uy",
    server: &[
        Server {
            protocol: Imap,
            socket: Starttls,
            hostname: "mail.buzon.uy",
            port: 143,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Starttls,
            hostname: "mail.buzon.uy",
            port: 587,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// c1.testrun.org.md: c1.testrun.org
static P_C1_TESTRUN_ORG: Provider = Provider {
    id: "c1.testrun.org",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/c1-testrun-org",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "c1.testrun.org",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "c1.testrun.org",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: Some(&[ConfigDefault {
        key: Config::MvboxMove,
        value: "0",
    }]),
    oauth2_authorizer: None,
};

// c2.testrun.org.md: c2.testrun.org
static P_C2_TESTRUN_ORG: Provider = Provider {
    id: "c2.testrun.org",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/c2-testrun-org",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "c2.testrun.org",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "c2.testrun.org",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: Some(&[ConfigDefault {
        key: Config::MvboxMove,
        value: "0",
    }]),
    oauth2_authorizer: None,
};

// c3.testrun.org.md: c3.testrun.org
static P_C3_TESTRUN_ORG: Provider = Provider {
    id: "c3.testrun.org",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/c3-testrun-org",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "c3.testrun.org",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "c3.testrun.org",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: Some(&[ConfigDefault {
        key: Config::MvboxMove,
        value: "0",
    }]),
    oauth2_authorizer: None,
};

// chello.at.md: chello.at
static P_CHELLO_AT: Provider = Provider {
    id: "chello.at",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/chello-at",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "mail.mymagenta.at",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "mail.mymagenta.at",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// comcast.md: xfinity.com, comcast.net
static P_COMCAST: Provider = Provider {
    id: "comcast",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/comcast",
    server: &[],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// dismail.de.md: dismail.de
static P_DISMAIL_DE: Provider = Provider {
    id: "dismail.de",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/dismail-de",
    server: &[],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// disroot.md: disroot.org
static P_DISROOT: Provider = Provider {
    id: "disroot",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/disroot",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "disroot.org",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Starttls,
            hostname: "disroot.org",
            port: 587,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// e.email.md: e.email
static P_E_EMAIL: Provider = Provider {
    id: "e.email",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/e-email",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "mail.ecloud.global",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Starttls,
            hostname: "mail.ecloud.global",
            port: 587,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// espiv.net.md: espiv.net
static P_ESPIV_NET: Provider = Provider {
    id: "espiv.net",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/espiv-net",
    server: &[],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// example.com.md: example.com, example.org, example.net
static P_EXAMPLE_COM: Provider = Provider {
    id: "example.com",
    status: Status::Broken,
    before_login_hint: "Hush this provider doesn't exist!",
    after_login_hint: "This provider doesn't really exist, so you can't use it :/ If you need an email provider for Delta Chat, take a look at providers.delta.chat!",
    overview_page: "https://providers.delta.chat/example-com",
    server: &[
        Server { protocol: Imap, socket: Ssl, hostname: "imap.example.com", port: 1337, username_pattern: Email },
        Server { protocol: Smtp, socket: Starttls, hostname: "smtp.example.com", port: 1337, username_pattern: Email },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// fastmail.md: 123mail.org, 150mail.com, 150ml.com, 16mail.com, 2-mail.com, 4email.net, 50mail.com, airpost.net, allmail.net, bestmail.us, cluemail.com, elitemail.org, emailcorner.net, emailengine.net, emailengine.org, emailgroups.net, emailplus.org, emailuser.net, eml.cc, f-m.fm, fast-email.com, fast-mail.org, fastem.com, fastemail.us, fastemailer.com, fastest.cc, fastimap.com, fastmail.cn, fastmail.co.uk, fastmail.com, fastmail.com.au, fastmail.de, fastmail.es, fastmail.fm, fastmail.fr, fastmail.im, fastmail.in, fastmail.jp, fastmail.mx, fastmail.net, fastmail.nl, fastmail.org, fastmail.se, fastmail.to, fastmail.tw, fastmail.uk, fastmail.us, fastmailbox.net, fastmessaging.com, fea.st, fmail.co.uk, fmailbox.com, fmgirl.com, fmguy.com, ftml.net, h-mail.us, hailmail.net, imap-mail.com, imap.cc, imapmail.org, inoutbox.com, internet-e-mail.com, internet-mail.org, internetemails.net, internetmailing.net, jetemail.net, justemail.net, letterboxes.org, mail-central.com, mail-page.com, mailandftp.com, mailas.com, mailbolt.com, mailc.net, mailcan.com, mailforce.net, mailftp.com, mailhaven.com, mailingaddress.org, mailite.com, mailmight.com, mailnew.com, mailsent.net, mailservice.ms, mailup.net, mailworks.org, ml1.net, mm.st, myfastmail.com, mymacmail.com, nospammail.net, ownmail.net, petml.com, postinbox.com, postpro.net, proinbox.com, promessage.com, realemail.net, reallyfast.biz, reallyfast.info, rushpost.com, sent.as, sent.at, sent.com, speedpost.net, speedymail.org, ssl-mail.com, swift-mail.com, the-fastest.net, the-quickest.com, theinternetemail.com, veryfast.biz, veryspeedy.net, warpmail.net, xsmail.com, yepmail.net, your-mail.com
static P_FASTMAIL: Provider = Provider {
    id: "fastmail",
    status: Status::Preparation,
    before_login_hint:
        "You must create an app-specific password for Delta Chat before you can log in.",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/fastmail",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "imap.fastmail.com",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "smtp.fastmail.com",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// firemail.de.md: firemail.at, firemail.de
static P_FIREMAIL_DE: Provider = Provider {
    id: "firemail.de",
    status: Status::Preparation,
    before_login_hint: "Firemail erlaubt nur bei bezahlten Accounts den vollen Zugriff auf das E-Mail-Protokoll. Wenn Sie nicht für Firemail bezahlen, verwenden Sie bitte einen anderen E-Mail-Anbieter.",
    after_login_hint: "Leider schränkt Firemail die maximale Gruppengröße ein. Je nach Bezahlmodell sind nur 5 bis 30 Gruppenmitglieder erlaubt.",
    overview_page: "https://providers.delta.chat/firemail-de",
    server: &[
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// five.chat.md: five.chat
static P_FIVE_CHAT: Provider = Provider {
    id: "five.chat",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/five-chat",
    server: &[],
    opt: ProviderOptions::new(),
    config_defaults: Some(&[
        ConfigDefault {
            key: Config::BccSelf,
            value: "1",
        },
        ConfigDefault {
            key: Config::SentboxWatch,
            value: "0",
        },
        ConfigDefault {
            key: Config::MvboxMove,
            value: "0",
        },
    ]),
    oauth2_authorizer: None,
};

// freenet.de.md: freenet.de
static P_FREENET_DE: Provider = Provider {
    id: "freenet.de",
    status: Status::Preparation,
    before_login_hint: "Um deine freenet.de E-Mail-Adresse mit Delta Chat zu benutzen, musst du erst auf der freenet.de-Webseite \"POP3/IMAP/SMTP\" aktivieren.",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/freenet-de",
    server: &[
        Server { protocol: Imap, socket: Ssl, hostname: "mx.freenet.de", port: 993, username_pattern: Email },
        Server { protocol: Smtp, socket: Starttls, hostname: "mx.freenet.de", port: 587, username_pattern: Email },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// gmail.md: gmail.com, googlemail.com, google.com
static P_GMAIL: Provider = Provider {
    id: "gmail",
    status: Status::Preparation,
    before_login_hint: "For Gmail accounts, you need to create an app-password if you have \"2-Step Verification\" enabled. If this setting is not available, you need to enable \"less secure apps\".",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/gmail",
    server: &[
        Server { protocol: Imap, socket: Ssl, hostname: "imap.gmail.com", port: 993, username_pattern: Email },
        Server { protocol: Smtp, socket: Ssl, hostname: "smtp.gmail.com", port: 465, username_pattern: Email },
    ],
    opt: ProviderOptions {
        delete_to_trash: true,
        ..ProviderOptions::new()
    },
    config_defaults: None,
    oauth2_authorizer: Some(Oauth2Authorizer::Gmail),
};

// gmx.net.md: gmx.net, gmx.de, gmx.at, gmx.ch, gmx.org, gmx.eu, gmx.info, gmx.biz, gmx.com
static P_GMX_NET: Provider = Provider {
    id: "gmx.net",
    status: Status::Preparation,
    before_login_hint: "You must allow IMAP access to your account before you can login.",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/gmx-net",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "imap.gmx.net",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "mail.gmx.net",
            port: 465,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Starttls,
            hostname: "mail.gmx.net",
            port: 587,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// hermes.radio.md: *.hermes.radio, *.aco-connexion.org
static P_HERMES_RADIO: Provider = Provider {
    id: "hermes.radio",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/hermes-radio",
    server: &[],
    opt: ProviderOptions {
        strict_tls: false,
        ..ProviderOptions::new()
    },
    config_defaults: Some(&[
        ConfigDefault {
            key: Config::MdnsEnabled,
            value: "0",
        },
        ConfigDefault {
            key: Config::E2eeEnabled,
            value: "0",
        },
        ConfigDefault {
            key: Config::ShowEmails,
            value: "2",
        },
    ]),
    oauth2_authorizer: None,
};

// hey.com.md: hey.com
static P_HEY_COM: Provider = Provider {
    id: "hey.com",
    status: Status::Broken,
    before_login_hint: "hey.com does not offer the standard IMAP e-mail protocol, so you cannot log in with Delta Chat to hey.com.",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/hey-com",
    server: &[
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// i.ua.md: i.ua
static P_I_UA: Provider = Provider {
    id: "i.ua",
    status: Status::Broken,
    before_login_hint: "Протокол IMAP не предоставляется и не планируется.",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/i-ua",
    server: &[],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// i3.net.md: i3.net
static P_I3_NET: Provider = Provider {
    id: "i3.net",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/i3-net",
    server: &[],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// icloud.md: icloud.com, me.com, mac.com
static P_ICLOUD: Provider = Provider {
    id: "icloud",
    status: Status::Preparation,
    before_login_hint: "You must create an app-specific password for Delta Chat before login.",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/icloud",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "imap.mail.me.com",
            port: 993,
            username_pattern: Emaillocalpart,
        },
        Server {
            protocol: Smtp,
            socket: Starttls,
            hostname: "smtp.mail.me.com",
            port: 587,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// infomaniak.com.md: ik.me
static P_INFOMANIAK_COM: Provider = Provider {
    id: "infomaniak.com",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/infomaniak-com",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "mail.infomaniak.com",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "mail.infomaniak.com",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions {
        max_smtp_rcpt_to: Some(10),
        ..ProviderOptions::new()
    },
    config_defaults: None,
    oauth2_authorizer: None,
};

// kolst.com.md: kolst.com
static P_KOLST_COM: Provider = Provider {
    id: "kolst.com",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/kolst-com",
    server: &[],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// kontent.com.md: kontent.com
static P_KONTENT_COM: Provider = Provider {
    id: "kontent.com",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/kontent-com",
    server: &[],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// mail.de.md: mail.de
static P_MAIL_DE: Provider = Provider {
    id: "mail.de",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/mail-de",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "imap.mail.de",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "smtp.mail.de",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// mail.ru.md: mail.ru, inbox.ru, internet.ru, bk.ru, list.ru
static P_MAIL_RU: Provider = Provider {
    id: "mail.ru",
    status: Status::Preparation,
    before_login_hint: "Вам необходимо сгенерировать \"пароль для внешнего приложения\" в веб-интерфейсе mail.ru, чтобы mail.ru работал с Delta Chat.",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/mail-ru",
    server: &[
        Server { protocol: Imap, socket: Ssl, hostname: "imap.mail.ru", port: 993, username_pattern: Email },
        Server { protocol: Smtp, socket: Ssl, hostname: "smtp.mail.ru", port: 465, username_pattern: Email },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// mail2tor.md: mail2tor.com
static P_MAIL2TOR: Provider = Provider {
    id: "mail2tor",
    status: Status::Preparation,
    before_login_hint: "Tor is needed to connect to the email servers.",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/mail2tor",
    server: &[
        Server {
            protocol: Imap,
            socket: Plain,
            hostname: "g77kjrad6bafzzyldqvffq6kxlsgphcygptxhnn4xlnktfgaqshilmyd.onion",
            port: 143,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Plain,
            hostname: "xc7tgk2c5onxni2wsy76jslfsitxjbbptejnqhw6gy2ft7khpevhc7ad.onion",
            port: 25,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// mailbox.org.md: mailbox.org, secure.mailbox.org
static P_MAILBOX_ORG: Provider = Provider {
    id: "mailbox.org",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/mailbox-org",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "imap.mailbox.org",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "smtp.mailbox.org",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// mailo.com.md: mailo.com
static P_MAILO_COM: Provider = Provider {
    id: "mailo.com",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/mailo-com",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "imap.mailo.com",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "smtp.mailo.com",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// nauta.cu.md: nauta.cu
static P_NAUTA_CU: Provider = Provider {
    id: "nauta.cu",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/nauta-cu",
    server: &[
        Server {
            protocol: Imap,
            socket: Starttls,
            hostname: "imap.nauta.cu",
            port: 143,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Starttls,
            hostname: "smtp.nauta.cu",
            port: 25,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions {
        max_smtp_rcpt_to: Some(20),
        strict_tls: false,
        ..ProviderOptions::new()
    },
    config_defaults: Some(&[
        ConfigDefault {
            key: Config::DeleteServerAfter,
            value: "1",
        },
        ConfigDefault {
            key: Config::BccSelf,
            value: "0",
        },
        ConfigDefault {
            key: Config::SentboxWatch,
            value: "0",
        },
        ConfigDefault {
            key: Config::MvboxMove,
            value: "0",
        },
        ConfigDefault {
            key: Config::MediaQuality,
            value: "1",
        },
        ConfigDefault {
            key: Config::FetchExistingMsgs,
            value: "0",
        },
    ]),
    oauth2_authorizer: None,
};

// naver.md: naver.com
static P_NAVER: Provider = Provider {
    id: "naver",
    status: Status::Preparation,
    before_login_hint: "Manually enabling IMAP/SMTP is required.",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/naver",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "imap.naver.com",
            port: 993,
            username_pattern: Emaillocalpart,
        },
        Server {
            protocol: Smtp,
            socket: Starttls,
            hostname: "smtp.naver.com",
            port: 587,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// nine.testrun.org.md: nine.testrun.org
static P_NINE_TESTRUN_ORG: Provider = Provider {
    id: "nine.testrun.org",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/nine-testrun-org",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "nine.testrun.org",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "nine.testrun.org",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: Some(&[ConfigDefault {
        key: Config::MvboxMove,
        value: "0",
    }]),
    oauth2_authorizer: None,
};

// nubo.coop.md: nubo.coop
static P_NUBO_COOP: Provider = Provider {
    id: "nubo.coop",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/nubo-coop",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "mail.nubo.coop",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "mail.nubo.coop",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// outlook.com.md: hotmail.com, outlook.com, office365.com, outlook.com.tr, live.com, outlook.de
static P_OUTLOOK_COM: Provider = Provider {
    id: "outlook.com",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/outlook-com",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "outlook.office365.com",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Starttls,
            hostname: "smtp.office365.com",
            port: 587,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// ouvaton.coop.md: ouvaton.org
static P_OUVATON_COOP: Provider = Provider {
    id: "ouvaton.coop",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/ouvaton-coop",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "imap.ouvaton.coop",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "smtp.ouvaton.coop",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// posteo.md: posteo.de, posteo.af, posteo.at, posteo.be, posteo.ca, posteo.ch, posteo.cl, posteo.co, posteo.co.uk, posteo.com.br, posteo.cr, posteo.cz, posteo.dk, posteo.ee, posteo.es, posteo.eu, posteo.fi, posteo.gl, posteo.gr, posteo.hn, posteo.hr, posteo.hu, posteo.ie, posteo.in, posteo.is, posteo.it, posteo.jp, posteo.la, posteo.li, posteo.lt, posteo.lu, posteo.me, posteo.mx, posteo.my, posteo.net, posteo.nl, posteo.no, posteo.nz, posteo.org, posteo.pe, posteo.pl, posteo.pm, posteo.pt, posteo.ro, posteo.ru, posteo.se, posteo.sg, posteo.si, posteo.tn, posteo.uk, posteo.us
static P_POSTEO: Provider = Provider {
    id: "posteo",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/posteo",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "posteo.de",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Imap,
            socket: Starttls,
            hostname: "posteo.de",
            port: 143,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "posteo.de",
            port: 465,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Starttls,
            hostname: "posteo.de",
            port: 587,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// protonmail.md: protonmail.com, protonmail.ch, pm.me
static P_PROTONMAIL: Provider = Provider {
    id: "protonmail",
    status: Status::Broken,
    before_login_hint: "Protonmail does not offer the standard IMAP e-mail protocol, so you cannot log in with Delta Chat to Protonmail.",
    after_login_hint: "To use Delta Chat with Protonmail, the IMAP bridge must be running in the background. If you have connectivity issues, double check whether it works as expected.",
    overview_page: "https://providers.delta.chat/protonmail",
    server: &[
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// qq.md: qq.com, foxmail.com
static P_QQ: Provider = Provider {
    id: "qq",
    status: Status::Preparation,
    before_login_hint: "Manually enabling IMAP/SMTP and creating an app-specific password for Delta Chat are required.",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/qq",
    server: &[
        Server { protocol: Imap, socket: Ssl, hostname: "imap.qq.com", port: 993, username_pattern: Emaillocalpart },
        Server { protocol: Smtp, socket: Ssl, hostname: "smtp.qq.com", port: 465, username_pattern: Email },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// riseup.net.md: riseup.net
static P_RISEUP_NET: Provider = Provider {
    id: "riseup.net",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/riseup-net",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "mail.riseup.net",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "mail.riseup.net",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// rogers.com.md: rogers.com
static P_ROGERS_COM: Provider = Provider {
    id: "rogers.com",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/rogers-com",
    server: &[],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// sonic.md: sonic.net
static P_SONIC: Provider = Provider {
    id: "sonic",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/sonic",
    server: &[],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// systemausfall.org.md: systemausfall.org, solidaris.me
static P_SYSTEMAUSFALL_ORG: Provider = Provider {
    id: "systemausfall.org",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/systemausfall-org",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "mail.systemausfall.org",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "mail.systemausfall.org",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// systemli.org.md: systemli.org
static P_SYSTEMLI_ORG: Provider = Provider {
    id: "systemli.org",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/systemli-org",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "mail.systemli.org",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "mail.systemli.org",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// t-online.md: t-online.de, magenta.de
static P_T_ONLINE: Provider = Provider {
    id: "t-online",
    status: Status::Preparation,
    before_login_hint: "To use Delta Chat with a T-Online email address, you need to create an app password in the web interface.",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/t-online",
    server: &[
        Server { protocol: Imap, socket: Ssl, hostname: "secureimap.t-online.de", port: 993, username_pattern: Email },
        Server { protocol: Smtp, socket: Ssl, hostname: "securesmtp.t-online.de", port: 465, username_pattern: Email },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// testrun.md: testrun.org
static P_TESTRUN: Provider = Provider {
    id: "testrun",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/testrun",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "testrun.org",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Imap,
            socket: Starttls,
            hostname: "testrun.org",
            port: 143,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Starttls,
            hostname: "testrun.org",
            port: 587,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: Some(&[
        ConfigDefault {
            key: Config::BccSelf,
            value: "1",
        },
        ConfigDefault {
            key: Config::SentboxWatch,
            value: "0",
        },
        ConfigDefault {
            key: Config::MvboxMove,
            value: "0",
        },
    ]),
    oauth2_authorizer: None,
};

// tiscali.it.md: tiscali.it
static P_TISCALI_IT: Provider = Provider {
    id: "tiscali.it",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/tiscali-it",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "imap.tiscali.it",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "smtp.tiscali.it",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// tutanota.md: tutanota.com, tutanota.de, tutamail.com, tuta.io, keemail.me
static P_TUTANOTA: Provider = Provider {
    id: "tutanota",
    status: Status::Broken,
    before_login_hint: "Tutanota does not offer the standard IMAP e-mail protocol, so you cannot log in with Delta Chat to Tutanota.",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/tutanota",
    server: &[
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// ukr.net.md: ukr.net
static P_UKR_NET: Provider = Provider {
    id: "ukr.net",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/ukr-net",
    server: &[],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// undernet.uy.md: undernet.uy
static P_UNDERNET_UY: Provider = Provider {
    id: "undernet.uy",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/undernet-uy",
    server: &[
        Server {
            protocol: Imap,
            socket: Starttls,
            hostname: "undernet.uy",
            port: 143,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Starttls,
            hostname: "undernet.uy",
            port: 587,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// vfemail.md: vfemail.net
static P_VFEMAIL: Provider = Provider {
    id: "vfemail",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/vfemail",
    server: &[],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// vivaldi.md: vivaldi.net
static P_VIVALDI: Provider = Provider {
    id: "vivaldi",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/vivaldi",
    server: &[
        Server {
            protocol: Imap,
            socket: Starttls,
            hostname: "imap.vivaldi.net",
            port: 143,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Starttls,
            hostname: "smtp.vivaldi.net",
            port: 587,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// vodafone.de.md: vodafone.de, vodafonemail.de
static P_VODAFONE_DE: Provider = Provider {
    id: "vodafone.de",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/vodafone-de",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "imap.vodafonemail.de",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Starttls,
            hostname: "smtp.vodafonemail.de",
            port: 587,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// web.de.md: web.de, email.de, flirt.ms, hallo.ms, kuss.ms, love.ms, magic.ms, singles.ms, cool.ms, kanzler.ms, okay.ms, party.ms, pop.ms, stars.ms, techno.ms, clever.ms, deutschland.ms, genial.ms, ich.ms, online.ms, smart.ms, wichtig.ms, action.ms, fussball.ms, joker.ms, planet.ms, power.ms
static P_WEB_DE: Provider = Provider {
    id: "web.de",
    status: Status::Preparation,
    before_login_hint: "You must allow IMAP access to your account before you can login.",
    after_login_hint: "Note: if you have your web.de spam settings too strict, you won't receive contact requests from new people. If you want to receive contact requests, you should disable the \"3-Wege-Spamschutz\" in the web.de settings.  Read how: https://hilfe.web.de/email/spam-und-viren/spamschutz-einstellungen.html",
    overview_page: "https://providers.delta.chat/web-de",
    server: &[
        Server { protocol: Imap, socket: Ssl, hostname: "imap.web.de", port: 993, username_pattern: Emaillocalpart },
        Server { protocol: Imap, socket: Starttls, hostname: "imap.web.de", port: 143, username_pattern: Emaillocalpart },
        Server { protocol: Smtp, socket: Starttls, hostname: "smtp.web.de", port: 587, username_pattern: Emaillocalpart },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// yahoo.md: yahoo.com, yahoo.de, yahoo.it, yahoo.fr, yahoo.es, yahoo.se, yahoo.co.uk, yahoo.co.nz, yahoo.com.au, yahoo.com.ar, yahoo.com.br, yahoo.com.mx, ymail.com, rocketmail.com, yahoodns.net
static P_YAHOO: Provider = Provider {
    id: "yahoo",
    status: Status::Preparation,
    before_login_hint: "To use Delta Chat with your Yahoo email address you have to create an \"App-Password\" in the account security screen.",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/yahoo",
    server: &[
        Server { protocol: Imap, socket: Ssl, hostname: "imap.mail.yahoo.com", port: 993, username_pattern: Email },
        Server { protocol: Smtp, socket: Ssl, hostname: "smtp.mail.yahoo.com", port: 465, username_pattern: Email },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// yandex.ru.md: yandex.com, yandex.by, yandex.kz, yandex.ru, yandex.ua, ya.ru, narod.ru
static P_YANDEX_RU: Provider = Provider {
    id: "yandex.ru",
    status: Status::Preparation,
    before_login_hint: "For Yandex accounts, you have to set IMAP protocol option turned on.",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/yandex-ru",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "imap.yandex.com",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "smtp.yandex.com",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: Some(Oauth2Authorizer::Yandex),
};

// yggmail.md: yggmail
static P_YGGMAIL: Provider = Provider {
    id: "yggmail",
    status: Status::Preparation,
    before_login_hint: "An Yggmail companion app needs to be installed on your device to access the Yggmail network.",
    after_login_hint: "Make sure, the Yggmail companion app runs whenever you want to use this account. Note, that you usually cannot write from @yggmail addresses to normal e-mail-addresses (as @gmx.net). However, you can create another account in the normal e-mail-network for this purpose.",
    overview_page: "https://providers.delta.chat/yggmail",
    server: &[
        Server { protocol: Imap, socket: Plain, hostname: "localhost", port: 1143, username_pattern: Email },
        Server { protocol: Smtp, socket: Plain, hostname: "localhost", port: 1025, username_pattern: Email },
    ],
    opt: ProviderOptions::new(),
    config_defaults: Some(&[
        ConfigDefault { key: Config::MvboxMove, value: "0" },
    ]),
    oauth2_authorizer: None,
};

// ziggo.nl.md: ziggo.nl
static P_ZIGGO_NL: Provider = Provider {
    id: "ziggo.nl",
    status: Status::Ok,
    before_login_hint: "",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/ziggo-nl",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "imap.ziggo.nl",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Starttls,
            hostname: "smtp.ziggo.nl",
            port: 587,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

// zoho.md: zohomail.eu, zohomail.com, zoho.com
static P_ZOHO: Provider = Provider {
    id: "zoho",
    status: Status::Preparation,
    before_login_hint: "To use Zoho Mail, you have to turn on IMAP in the Zoho Mail backend.",
    after_login_hint: "",
    overview_page: "https://providers.delta.chat/zoho",
    server: &[
        Server {
            protocol: Imap,
            socket: Ssl,
            hostname: "imap.zoho.eu",
            port: 993,
            username_pattern: Email,
        },
        Server {
            protocol: Smtp,
            socket: Ssl,
            hostname: "smtp.zoho.eu",
            port: 465,
            username_pattern: Email,
        },
    ],
    opt: ProviderOptions::new(),
    config_defaults: None,
    oauth2_authorizer: None,
};

pub(crate) static PROVIDER_DATA: [(&str, &Provider); 318] = [
    ("163.com", &P_163),
    ("aktivix.org", &P_AKTIVIX_ORG),
    ("aol.com", &P_AOL),
    ("arcor.de", &P_ARCOR_DE),
    ("autistici.org", &P_AUTISTICI_ORG),
    ("delta.blinzeln.de", &P_BLINDZELN_ORG),
    ("delta.blindzeln.org", &P_BLINDZELN_ORG),
    ("bluewin.ch", &P_BLUEWIN_CH),
    ("buzon.uy", &P_BUZON_UY),
    ("c1.testrun.org", &P_C1_TESTRUN_ORG),
    ("c2.testrun.org", &P_C2_TESTRUN_ORG),
    ("c3.testrun.org", &P_C3_TESTRUN_ORG),
    ("chello.at", &P_CHELLO_AT),
    ("xfinity.com", &P_COMCAST),
    ("comcast.net", &P_COMCAST),
    ("dismail.de", &P_DISMAIL_DE),
    ("disroot.org", &P_DISROOT),
    ("e.email", &P_E_EMAIL),
    ("espiv.net", &P_ESPIV_NET),
    ("example.com", &P_EXAMPLE_COM),
    ("example.org", &P_EXAMPLE_COM),
    ("example.net", &P_EXAMPLE_COM),
    ("123mail.org", &P_FASTMAIL),
    ("150mail.com", &P_FASTMAIL),
    ("150ml.com", &P_FASTMAIL),
    ("16mail.com", &P_FASTMAIL),
    ("2-mail.com", &P_FASTMAIL),
    ("4email.net", &P_FASTMAIL),
    ("50mail.com", &P_FASTMAIL),
    ("airpost.net", &P_FASTMAIL),
    ("allmail.net", &P_FASTMAIL),
    ("bestmail.us", &P_FASTMAIL),
    ("cluemail.com", &P_FASTMAIL),
    ("elitemail.org", &P_FASTMAIL),
    ("emailcorner.net", &P_FASTMAIL),
    ("emailengine.net", &P_FASTMAIL),
    ("emailengine.org", &P_FASTMAIL),
    ("emailgroups.net", &P_FASTMAIL),
    ("emailplus.org", &P_FASTMAIL),
    ("emailuser.net", &P_FASTMAIL),
    ("eml.cc", &P_FASTMAIL),
    ("f-m.fm", &P_FASTMAIL),
    ("fast-email.com", &P_FASTMAIL),
    ("fast-mail.org", &P_FASTMAIL),
    ("fastem.com", &P_FASTMAIL),
    ("fastemail.us", &P_FASTMAIL),
    ("fastemailer.com", &P_FASTMAIL),
    ("fastest.cc", &P_FASTMAIL),
    ("fastimap.com", &P_FASTMAIL),
    ("fastmail.cn", &P_FASTMAIL),
    ("fastmail.co.uk", &P_FASTMAIL),
    ("fastmail.com", &P_FASTMAIL),
    ("fastmail.com.au", &P_FASTMAIL),
    ("fastmail.de", &P_FASTMAIL),
    ("fastmail.es", &P_FASTMAIL),
    ("fastmail.fm", &P_FASTMAIL),
    ("fastmail.fr", &P_FASTMAIL),
    ("fastmail.im", &P_FASTMAIL),
    ("fastmail.in", &P_FASTMAIL),
    ("fastmail.jp", &P_FASTMAIL),
    ("fastmail.mx", &P_FASTMAIL),
    ("fastmail.net", &P_FASTMAIL),
    ("fastmail.nl", &P_FASTMAIL),
    ("fastmail.org", &P_FASTMAIL),
    ("fastmail.se", &P_FASTMAIL),
    ("fastmail.to", &P_FASTMAIL),
    ("fastmail.tw", &P_FASTMAIL),
    ("fastmail.uk", &P_FASTMAIL),
    ("fastmail.us", &P_FASTMAIL),
    ("fastmailbox.net", &P_FASTMAIL),
    ("fastmessaging.com", &P_FASTMAIL),
    ("fea.st", &P_FASTMAIL),
    ("fmail.co.uk", &P_FASTMAIL),
    ("fmailbox.com", &P_FASTMAIL),
    ("fmgirl.com", &P_FASTMAIL),
    ("fmguy.com", &P_FASTMAIL),
    ("ftml.net", &P_FASTMAIL),
    ("h-mail.us", &P_FASTMAIL),
    ("hailmail.net", &P_FASTMAIL),
    ("imap-mail.com", &P_FASTMAIL),
    ("imap.cc", &P_FASTMAIL),
    ("imapmail.org", &P_FASTMAIL),
    ("inoutbox.com", &P_FASTMAIL),
    ("internet-e-mail.com", &P_FASTMAIL),
    ("internet-mail.org", &P_FASTMAIL),
    ("internetemails.net", &P_FASTMAIL),
    ("internetmailing.net", &P_FASTMAIL),
    ("jetemail.net", &P_FASTMAIL),
    ("justemail.net", &P_FASTMAIL),
    ("letterboxes.org", &P_FASTMAIL),
    ("mail-central.com", &P_FASTMAIL),
    ("mail-page.com", &P_FASTMAIL),
    ("mailandftp.com", &P_FASTMAIL),
    ("mailas.com", &P_FASTMAIL),
    ("mailbolt.com", &P_FASTMAIL),
    ("mailc.net", &P_FASTMAIL),
    ("mailcan.com", &P_FASTMAIL),
    ("mailforce.net", &P_FASTMAIL),
    ("mailftp.com", &P_FASTMAIL),
    ("mailhaven.com", &P_FASTMAIL),
    ("mailingaddress.org", &P_FASTMAIL),
    ("mailite.com", &P_FASTMAIL),
    ("mailmight.com", &P_FASTMAIL),
    ("mailnew.com", &P_FASTMAIL),
    ("mailsent.net", &P_FASTMAIL),
    ("mailservice.ms", &P_FASTMAIL),
    ("mailup.net", &P_FASTMAIL),
    ("mailworks.org", &P_FASTMAIL),
    ("ml1.net", &P_FASTMAIL),
    ("mm.st", &P_FASTMAIL),
    ("myfastmail.com", &P_FASTMAIL),
    ("mymacmail.com", &P_FASTMAIL),
    ("nospammail.net", &P_FASTMAIL),
    ("ownmail.net", &P_FASTMAIL),
    ("petml.com", &P_FASTMAIL),
    ("postinbox.com", &P_FASTMAIL),
    ("postpro.net", &P_FASTMAIL),
    ("proinbox.com", &P_FASTMAIL),
    ("promessage.com", &P_FASTMAIL),
    ("realemail.net", &P_FASTMAIL),
    ("reallyfast.biz", &P_FASTMAIL),
    ("reallyfast.info", &P_FASTMAIL),
    ("rushpost.com", &P_FASTMAIL),
    ("sent.as", &P_FASTMAIL),
    ("sent.at", &P_FASTMAIL),
    ("sent.com", &P_FASTMAIL),
    ("speedpost.net", &P_FASTMAIL),
    ("speedymail.org", &P_FASTMAIL),
    ("ssl-mail.com", &P_FASTMAIL),
    ("swift-mail.com", &P_FASTMAIL),
    ("the-fastest.net", &P_FASTMAIL),
    ("the-quickest.com", &P_FASTMAIL),
    ("theinternetemail.com", &P_FASTMAIL),
    ("veryfast.biz", &P_FASTMAIL),
    ("veryspeedy.net", &P_FASTMAIL),
    ("warpmail.net", &P_FASTMAIL),
    ("xsmail.com", &P_FASTMAIL),
    ("yepmail.net", &P_FASTMAIL),
    ("your-mail.com", &P_FASTMAIL),
    ("firemail.at", &P_FIREMAIL_DE),
    ("firemail.de", &P_FIREMAIL_DE),
    ("five.chat", &P_FIVE_CHAT),
    ("freenet.de", &P_FREENET_DE),
    ("gmail.com", &P_GMAIL),
    ("googlemail.com", &P_GMAIL),
    ("google.com", &P_GMAIL),
    ("gmx.net", &P_GMX_NET),
    ("gmx.de", &P_GMX_NET),
    ("gmx.at", &P_GMX_NET),
    ("gmx.ch", &P_GMX_NET),
    ("gmx.org", &P_GMX_NET),
    ("gmx.eu", &P_GMX_NET),
    ("gmx.info", &P_GMX_NET),
    ("gmx.biz", &P_GMX_NET),
    ("gmx.com", &P_GMX_NET),
    ("*.hermes.radio", &P_HERMES_RADIO),
    ("*.aco-connexion.org", &P_HERMES_RADIO),
    ("hey.com", &P_HEY_COM),
    ("i.ua", &P_I_UA),
    ("i3.net", &P_I3_NET),
    ("icloud.com", &P_ICLOUD),
    ("me.com", &P_ICLOUD),
    ("mac.com", &P_ICLOUD),
    ("ik.me", &P_INFOMANIAK_COM),
    ("kolst.com", &P_KOLST_COM),
    ("kontent.com", &P_KONTENT_COM),
    ("mail.de", &P_MAIL_DE),
    ("mail.ru", &P_MAIL_RU),
    ("inbox.ru", &P_MAIL_RU),
    ("internet.ru", &P_MAIL_RU),
    ("bk.ru", &P_MAIL_RU),
    ("list.ru", &P_MAIL_RU),
    ("mail2tor.com", &P_MAIL2TOR),
    ("mailbox.org", &P_MAILBOX_ORG),
    ("secure.mailbox.org", &P_MAILBOX_ORG),
    ("mailo.com", &P_MAILO_COM),
    ("nauta.cu", &P_NAUTA_CU),
    ("naver.com", &P_NAVER),
    ("nine.testrun.org", &P_NINE_TESTRUN_ORG),
    ("nubo.coop", &P_NUBO_COOP),
    ("hotmail.com", &P_OUTLOOK_COM),
    ("outlook.com", &P_OUTLOOK_COM),
    ("office365.com", &P_OUTLOOK_COM),
    ("outlook.com.tr", &P_OUTLOOK_COM),
    ("live.com", &P_OUTLOOK_COM),
    ("outlook.de", &P_OUTLOOK_COM),
    ("ouvaton.org", &P_OUVATON_COOP),
    ("posteo.de", &P_POSTEO),
    ("posteo.af", &P_POSTEO),
    ("posteo.at", &P_POSTEO),
    ("posteo.be", &P_POSTEO),
    ("posteo.ca", &P_POSTEO),
    ("posteo.ch", &P_POSTEO),
    ("posteo.cl", &P_POSTEO),
    ("posteo.co", &P_POSTEO),
    ("posteo.co.uk", &P_POSTEO),
    ("posteo.com.br", &P_POSTEO),
    ("posteo.cr", &P_POSTEO),
    ("posteo.cz", &P_POSTEO),
    ("posteo.dk", &P_POSTEO),
    ("posteo.ee", &P_POSTEO),
    ("posteo.es", &P_POSTEO),
    ("posteo.eu", &P_POSTEO),
    ("posteo.fi", &P_POSTEO),
    ("posteo.gl", &P_POSTEO),
    ("posteo.gr", &P_POSTEO),
    ("posteo.hn", &P_POSTEO),
    ("posteo.hr", &P_POSTEO),
    ("posteo.hu", &P_POSTEO),
    ("posteo.ie", &P_POSTEO),
    ("posteo.in", &P_POSTEO),
    ("posteo.is", &P_POSTEO),
    ("posteo.it", &P_POSTEO),
    ("posteo.jp", &P_POSTEO),
    ("posteo.la", &P_POSTEO),
    ("posteo.li", &P_POSTEO),
    ("posteo.lt", &P_POSTEO),
    ("posteo.lu", &P_POSTEO),
    ("posteo.me", &P_POSTEO),
    ("posteo.mx", &P_POSTEO),
    ("posteo.my", &P_POSTEO),
    ("posteo.net", &P_POSTEO),
    ("posteo.nl", &P_POSTEO),
    ("posteo.no", &P_POSTEO),
    ("posteo.nz", &P_POSTEO),
    ("posteo.org", &P_POSTEO),
    ("posteo.pe", &P_POSTEO),
    ("posteo.pl", &P_POSTEO),
    ("posteo.pm", &P_POSTEO),
    ("posteo.pt", &P_POSTEO),
    ("posteo.ro", &P_POSTEO),
    ("posteo.ru", &P_POSTEO),
    ("posteo.se", &P_POSTEO),
    ("posteo.sg", &P_POSTEO),
    ("posteo.si", &P_POSTEO),
    ("posteo.tn", &P_POSTEO),
    ("posteo.uk", &P_POSTEO),
    ("posteo.us", &P_POSTEO),
    ("protonmail.com", &P_PROTONMAIL),
    ("protonmail.ch", &P_PROTONMAIL),
    ("pm.me", &P_PROTONMAIL),
    ("qq.com", &P_QQ),
    ("foxmail.com", &P_QQ),
    ("riseup.net", &P_RISEUP_NET),
    ("rogers.com", &P_ROGERS_COM),
    ("sonic.net", &P_SONIC),
    ("systemausfall.org", &P_SYSTEMAUSFALL_ORG),
    ("solidaris.me", &P_SYSTEMAUSFALL_ORG),
    ("systemli.org", &P_SYSTEMLI_ORG),
    ("t-online.de", &P_T_ONLINE),
    ("magenta.de", &P_T_ONLINE),
    ("testrun.org", &P_TESTRUN),
    ("tiscali.it", &P_TISCALI_IT),
    ("tutanota.com", &P_TUTANOTA),
    ("tutanota.de", &P_TUTANOTA),
    ("tutamail.com", &P_TUTANOTA),
    ("tuta.io", &P_TUTANOTA),
    ("keemail.me", &P_TUTANOTA),
    ("ukr.net", &P_UKR_NET),
    ("undernet.uy", &P_UNDERNET_UY),
    ("vfemail.net", &P_VFEMAIL),
    ("vivaldi.net", &P_VIVALDI),
    ("vodafone.de", &P_VODAFONE_DE),
    ("vodafonemail.de", &P_VODAFONE_DE),
    ("web.de", &P_WEB_DE),
    ("email.de", &P_WEB_DE),
    ("flirt.ms", &P_WEB_DE),
    ("hallo.ms", &P_WEB_DE),
    ("kuss.ms", &P_WEB_DE),
    ("love.ms", &P_WEB_DE),
    ("magic.ms", &P_WEB_DE),
    ("singles.ms", &P_WEB_DE),
    ("cool.ms", &P_WEB_DE),
    ("kanzler.ms", &P_WEB_DE),
    ("okay.ms", &P_WEB_DE),
    ("party.ms", &P_WEB_DE),
    ("pop.ms", &P_WEB_DE),
    ("stars.ms", &P_WEB_DE),
    ("techno.ms", &P_WEB_DE),
    ("clever.ms", &P_WEB_DE),
    ("deutschland.ms", &P_WEB_DE),
    ("genial.ms", &P_WEB_DE),
    ("ich.ms", &P_WEB_DE),
    ("online.ms", &P_WEB_DE),
    ("smart.ms", &P_WEB_DE),
    ("wichtig.ms", &P_WEB_DE),
    ("action.ms", &P_WEB_DE),
    ("fussball.ms", &P_WEB_DE),
    ("joker.ms", &P_WEB_DE),
    ("planet.ms", &P_WEB_DE),
    ("power.ms", &P_WEB_DE),
    ("yahoo.com", &P_YAHOO),
    ("yahoo.de", &P_YAHOO),
    ("yahoo.it", &P_YAHOO),
    ("yahoo.fr", &P_YAHOO),
    ("yahoo.es", &P_YAHOO),
    ("yahoo.se", &P_YAHOO),
    ("yahoo.co.uk", &P_YAHOO),
    ("yahoo.co.nz", &P_YAHOO),
    ("yahoo.com.au", &P_YAHOO),
    ("yahoo.com.ar", &P_YAHOO),
    ("yahoo.com.br", &P_YAHOO),
    ("yahoo.com.mx", &P_YAHOO),
    ("ymail.com", &P_YAHOO),
    ("rocketmail.com", &P_YAHOO),
    ("yahoodns.net", &P_YAHOO),
    ("yandex.com", &P_YANDEX_RU),
    ("yandex.by", &P_YANDEX_RU),
    ("yandex.kz", &P_YANDEX_RU),
    ("yandex.ru", &P_YANDEX_RU),
    ("yandex.ua", &P_YANDEX_RU),
    ("ya.ru", &P_YANDEX_RU),
    ("narod.ru", &P_YANDEX_RU),
    ("yggmail", &P_YGGMAIL),
    ("ziggo.nl", &P_ZIGGO_NL),
    ("zohomail.eu", &P_ZOHO),
    ("zohomail.com", &P_ZOHO),
    ("zoho.com", &P_ZOHO),
];

fn modify(x : Server) -> Moserver {
    let re  = Moserver{
        r#type : x.protocol,
        hostname : x.hostname,
        port : x.port.to_string(),
        socketType : x.socket,
        authentication : ""
    };
    return re;
}

use std::io::Write;

fn main() {
    println!("Hello, world!");
    //println!("{:?}", PROVIDER_DATA);
    let mut file = std::fs::File::create("data.txt").expect("create failed");
    
    for i in PROVIDER_DATA.iter() {
    	let domain = i.0;
    	let info = i.1;
    	let mut re = Result{
    		domain, 
    		DeltaChat: Autoconfig{
    			incomingServers: Vec::new(), 
    			outgoingServers: Vec::new()
    		}
    	};
    	
    	for j in info.server{
    	    let cur = modify(*j);
    	    if cur.r#type == Imap{
    	    	re.DeltaChat.incomingServers.push(cur);
    	    } else {
    	    	re.DeltaChat.outgoingServers.push(cur);
    	    }
    	    
    	}
    	let sdata = serde_json::to_string(&re);
    	let sdata = sdata.unwrap();
    	file.write_all(sdata.as_bytes()).expect("write failed");
    	file.write_all("\n".as_bytes()).expect("write failed");
    	//println!("Serialized data:\n{}", sdata);
    }
    
    
}
