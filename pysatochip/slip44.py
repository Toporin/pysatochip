# Format for each row:
# [ constant, coinSymbol, coinName ]
# from https://github.com/bitcoinjs/bip44-constants/blob/master/index.js
# added symbol TEST for Testnet instead of ''
LIST_SLIP44_RAW = [
  [0x80000000, 'BTC', 'Bitcoin'],
  [0x80000002, 'LTC', 'Litecoin'],
  #[0x80000003, 'DOGE', 'Dogecoin'],
  #[0x80000005, 'DASH', 'Dash'],
  [0x80000009, 'XCP', 'Counterparty'],
  [0x8000003c, 'ETH', 'Ether'],
  #[0x8000003d, 'ETC', 'Ether Classic'],
  #[0x80000089, 'RBTC', 'RSK'],
  [0x80000091, 'BCH', 'Bitcoin Cash'],
  #[0x80000207, 'BSC', 'Binance Smart Chain'],
]
LIST_SLIP44= [item[1] for item in LIST_SLIP44_RAW]
DICT_SLIP44_BY_CODE= {item[0]: item[1] for item in LIST_SLIP44_RAW}
DICT_SLIP44_BY_SYMBOL=  {item[1]: item[0] for item in LIST_SLIP44_RAW}

LIST_SLIP44_TOKEN_SUPPORT= ['ETH', 'ETC', 'BSC', 'XCP']