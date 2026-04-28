from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smbconnection import SMBConnection
from .utils import log

def _dedupe(values):
    seen = set()
    result = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result

def _lookup_candidates(profile_name, domain):
    candidates = [profile_name]

    # Windows may name a domain profile directory as user.DOMAIN even though the
    # account name that LSA can resolve is DOMAIN\user or just user.
    if "." in profile_name:
        account_name, profile_domain = profile_name.rsplit(".", 1)
        candidates.extend([
            profile_domain + "\\" + account_name,
            domain + "\\" + account_name if domain and domain.upper() != "WORKGROUP" else None,
            account_name,
        ])
    elif domain and domain.upper() != "WORKGROUP":
        candidates.append(domain + "\\" + profile_name)

    return _dedupe(candidates)

def _sid_from_lookup_response(resp):
    translated_sid = resp['TranslatedSids']['Sids'][0]
    rid = translated_sid['RelativeId']
    domain_index = translated_sid['DomainIndex']

    try:
        domain_sid = resp['ReferencedDomains']['Domains'][domain_index]['Sid'].formatCanonical()
    except Exception:
        return None

    return f"{domain_sid}-{rid}"

def get_user_sids(target, username, auth_value, domain, users, auth_type="password", existing_smb_conn=None):
    """Get SIDs for the specified users using the same authentication method as the main connection."""
    # List of system accounts to skip
    system_accounts = {
        'All Users', 'Default', 'Default User', 'Public', 
        'desktop.ini', 'Public Downloads'
    }
    
    # Filter out system accounts
    filtered_users = [user for user in users if user not in system_accounts]
    
    try:
        # Use existing SMB connection if provided
        if existing_smb_conn:
            smb_conn = existing_smb_conn
        else:
            smb_conn = SMBConnection(target, target, sess_port=445)
            # Use the same auth method as the main connection
            if auth_type == "password":
                smb_conn.login(username, auth_value, domain)
            elif auth_type == "hash":
                if ':' in auth_value:
                    lm_hash, nt_hash = auth_value.split(':')
                else:
                    lm_hash = 'aad3b435b51404eeaad3b435b51404ee'
                    nt_hash = auth_value
                smb_conn.login(username, '', domain, lmhash=lm_hash, nthash=nt_hash)
        
        log.info(f"Retrieving SIDs for users on {target}")
        
        stringbinding = r'ncacn_np:%s[\pipe\lsarpc]' % target
        log.debug(f"Stringbinding: {stringbinding}")
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(445)

        # Set credentials based on auth type
        if auth_type == "password":
            rpctransport.set_credentials(username, auth_value, domain)
        elif auth_type == "hash":
            if ':' in auth_value:
                lm_hash, nt_hash = auth_value.split(':')
            else:
                lm_hash = 'aad3b435b51404eeaad3b435b51404ee'
                nt_hash = auth_value
            rpctransport.set_credentials(username, '', domain, lm_hash, nt_hash)

        try:
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(lsat.MSRPC_UUID_LSAT)

            resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
            policy_handle = resp['PolicyHandle']

            user_sids = {}
            for user in filtered_users:
                last_error = None
                for candidate in _lookup_candidates(user, domain):
                    try:
                        resp = lsat.hLsarLookupNames2(
                            dce,
                            policy_handle,
                            (candidate,),
                            lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
                        )
                        user_sid = _sid_from_lookup_response(resp)
                        if not user_sid:
                            last_error = "lookup response did not include a referenced domain SID"
                            continue

                        user_sids[user] = user_sid
                        if candidate == user:
                            log.info(f"SID for {user}: {user_sid}")
                        else:
                            log.info(f"SID for {user}: {user_sid} (resolved as {candidate})")
                        break
                    except DCERPCException as e:
                        last_error = str(e)
                        log.debug(f"SID lookup candidate failed for {user} as {candidate}: {last_error}")

                if user not in user_sids:
                    log.warning(f"Error retrieving SID for {user}: {last_error}")

            dce.disconnect()
            return user_sids

        except Exception as e:
            log.error(f"Error in get_user_sids RPC operations: {str(e)}")
            return {}

    except Exception as e:
        log.error(f"Error in get_user_sids: {str(e)}")
        return {}
