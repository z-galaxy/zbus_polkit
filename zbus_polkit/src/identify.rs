use std::collections::HashMap;

use crate::error::Error;
use nix::unistd::Uid;
use serde::{Deserialize, Serialize};
use zbus::zvariant::Type;

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct Identity<'a> {
    identity_kind: &'a str,
    identity_details: HashMap<&'a str, zbus::zvariant::Value<'a>>,
}

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
