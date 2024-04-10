// pulls in client keys from /keys/clients and exports them

export type Client = {
    keys: Record<string, string>;
};

export const clients: Record<string, Client> = {
    'test_client': {
        keys: {
            'test_id': 
`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCMaJVmGtHyibF1Gylqgi1ghl4O
1wvcVif+3LneNAcpO0zXFGKzuPRaKXPaJYNxtii96TcUH1iB2Im0QQwEl5voY4Cz
i1AzxDWc3/i+fjGYY0La6c1CP0vIfkvUj8odc592R3BuCfFxuH0s6KCpKPdzihoM
Z75PpRfp2otvpmP3+wIDAQAB
-----END PUBLIC KEY-----`
        }
    }
}
