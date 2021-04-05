# AFMA Protocol Consensus Algorithm

## Instructions to Run

1. Clone the github repo and cd into directory

2. cd into generate_keys and build program
```
cd src/generate_keys
go build generate_keys.go
```

3. Generate the number of keys based on the number of peers you will be running
```
./generate_keys -numPeers=<#>
```

4. cd into afma, and build program
```
cd ../..
go build peer.go
```

5. Using multiple terminal instances, start running the peers
```
go run peer.go -i=<peer index #> -n<total # of peers>
```
