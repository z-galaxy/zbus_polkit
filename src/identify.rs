use static_assertions::assert_impl_all;

use serde::{Deserialize, Serialize};

use crate::Error;
use std::collections::HashMap;
use zbus::zvariant::{Type, Value};

/// This struct describes identities such as UNIX users and UNIX groups. It is typically used to
/// check if a given process is authorized for an action.
///
/// The following kinds of identities are known:
///
/// * Unix User. `identity_kind` should be set to `unix-user` with key uid (of type uint32).
///
/// * Unix Group. `identity_kind` should be set to `unix-group` with key gid (of type uint32).
#[derive(Debug, Type, Serialize, Deserialize)]
pub struct Identity<'a> {
    pub identity_kind: &'a str,

    pub identity_details: HashMap<&'a str, Value<'a>>,
}

assert_impl_all!(Identity<'_>: Send, Sync, Unpin);

/// This is the identify type to confirm the session
///
/// The following kinds of identities are known:
///
/// * Unix User. `identity_kind` should be set to `unix-user` with key uid (of type uint32).
///
/// * Unix Group. `identity_kind` should be set to `unix-group` with key gid (of type uint32).
///
/// * UnixNet Group. `identity_kind` should be set to `unix-netgroup`with key gid (of type uint32),
#[derive(Debug, Serialize, Deserialize, Type)]
pub enum IdentityType {
    UnixUser,
    UnixGroup,
    UnixNetGroup,
}

impl<'a> Identity<'a> {
    pub fn get_type(&self) -> Result<IdentityType, Error> {
        match self.identity_kind {
            "unix-user" => Ok(IdentityType::UnixUser),
            "unix-group" => Ok(IdentityType::UnixGroup),
            "unix-netgroup" => Ok(IdentityType::UnixNetGroup),
            _ => Err(Error::SessionUnknown(self.identity_kind.to_owned())),
        }
    }
}

use nix::unistd::{Uid, User};

impl<'a> TryInto<UnixUser> for Identity<'a> {
    type Error = Error;
    fn try_into(self) -> Result<UnixUser, Self::Error> {
        if !matches!(self.get_type()?, IdentityType::UnixUser) {
            return Err(Error::SessionUnmatch);
        }
        let uid = self
            .identity_details
            .get("uid")
            .ok_or(Error::SessionInnerError)?;
        let uid: u32 = uid.try_into().map_err(|_| Error::SessionInnerError)?;
        Ok(UnixUser { uid })
    }
}

impl<'a> TryInto<UnixUser> for &Identity<'a> {
    type Error = Error;
    fn try_into(self) -> Result<UnixUser, Self::Error> {
        if !matches!(self.get_type()?, IdentityType::UnixUser) {
            return Err(Error::SessionUnmatch);
        }
        let uid = self
            .identity_details
            .get("uid")
            .ok_or(Error::SessionInnerError)?;
        let uid: u32 = uid.try_into().map_err(|_| Error::SessionInnerError)?;
        Ok(UnixUser { uid })
    }
}
impl<'a> TryInto<UnixGroup> for Identity<'a> {
    type Error = Error;
    fn try_into(self) -> Result<UnixGroup, Self::Error> {
        if !matches!(self.get_type()?, IdentityType::UnixGroup) {
            return Err(Error::SessionUnmatch);
        }
        let gid = self
            .identity_details
            .get("gid")
            .ok_or(Error::SessionInnerError)?;
        let gid: u32 = gid.try_into().map_err(|_| Error::SessionInnerError)?;
        Ok(UnixGroup { gid })
    }
}

impl<'a> TryInto<UnixGroup> for &Identity<'a> {
    type Error = Error;
    fn try_into(self) -> Result<UnixGroup, Self::Error> {
        if !matches!(self.get_type()?, IdentityType::UnixGroup) {
            return Err(Error::SessionUnmatch);
        }
        let gid = self
            .identity_details
            .get("gid")
            .ok_or(Error::SessionInnerError)?;
        let gid: u32 = gid.try_into().map_err(|_| Error::SessionInnerError)?;
        Ok(UnixGroup { gid })
    }
}

impl<'a> TryInto<UnixNetGroup> for &Identity<'a> {
    type Error = Error;
    fn try_into(self) -> Result<UnixNetGroup, Self::Error> {
        if !matches!(self.get_type()?, IdentityType::UnixGroup) {
            return Err(Error::SessionUnmatch);
        }
        let name = self
            .identity_details
            .get("name")
            .ok_or(Error::SessionInnerError)?;
        let name: String = name.try_into().map_err(|_| Error::SessionInnerError)?;
        Ok(UnixNetGroup { name })
    }
}

impl<'a> TryInto<UnixNetGroup> for Identity<'a> {
    type Error = Error;
    fn try_into(self) -> Result<UnixNetGroup, Self::Error> {
        if !matches!(self.get_type()?, IdentityType::UnixGroup) {
            return Err(Error::SessionUnmatch);
        }
        let name = self
            .identity_details
            .get("name")
            .ok_or(Error::SessionInnerError)?;
        let name: String = name.try_into().map_err(|_| Error::SessionInnerError)?;
        Ok(UnixNetGroup { name })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UnixUser {
    pub uid: u32,
}

impl UnixUser {
    pub fn user(&self) -> Result<User, Error> {
        let uid = self.uid.into();
        nix::unistd::User::from_uid(uid)?.ok_or(Error::UserNotFound(uid.as_raw()))
    }
}

impl From<UnixUser> for Uid {
    fn from(val: UnixUser) -> Self {
        val.uid.into()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UnixGroup {
    pub gid: u32,
}

#[derive(Debug, Clone)]
pub struct UnixNetGroup {
    pub name: String,
}
