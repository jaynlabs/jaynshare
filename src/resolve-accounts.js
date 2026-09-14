import { importCredentials } from './oauth.js';

// Config accounts with credentials resolved; entries without a usable credential are dropped.
export async function resolveAccounts(config) {
  const accounts = [];
  for (const acct of config.accounts) {
    if (acct.type === 'oauth') {
      if (acct.importFrom) {
        try {
          const creds = await importCredentials(acct.importFrom);
          if (!creds.accessToken) {
            console.error(`No token in ${acct.importFrom} for "${acct.name}", skipping`);
            continue;
          }
          accounts.push({ ...acct, ...creds }); // keep every config field, not just the credential
          console.log(`Imported "${acct.name}" from ${acct.importFrom}`);
        } catch (err) {
          console.error(`Failed to import "${acct.name}": ${err.message}`);
        }
      } else if (acct.accessToken) {
        accounts.push(acct);
      } else {
        console.error(`No token for "${acct.name}", skipping`);
      }
    } else if (acct.type === 'apikey' && acct.apiKey) {
      accounts.push(acct);
    }
  }
  return accounts;
}
