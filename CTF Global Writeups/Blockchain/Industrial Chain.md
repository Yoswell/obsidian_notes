# Industrial Chain - TKM 2025
Flicker ha recorrido silenciosamente su lógica de control descentralizado, revirtiendo las condiciones de anulación en su contrato inteligente. El interruptor principal parece activado, pero los bloqueos de seguridad siguen vigentes a nivel de contrato. Tu misión: Recuperar el control manual. ¿Podrías revisar la lógica del contrato inteligente y ejecutar la secuencia correcta para anular el sabotaje?

## Solidity Code
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Challenge {
	bool public emergencyShutdown = false;
	bool public systemActivated = false;
	bool public you_solved_it = false;
	address public operator;
	
	constructor() {
		operator = msg.sender;
	}

	function engageMainSwitch() external returns (bool) {
		systemActivated = true;
		return true;
	}
	
	function pressOverrideButton() external returns (bool) {
		require(systemActivated, "System not activated");
		you_solved_it = true;
		return true;
	}
	
	function isSolved() external view returns (bool) {
		return you_solved_it;
	}
	
	function checkSystem() external view returns (string memory) {
		if (you_solved_it) {
			return "System Online Mission Accomplished!";
		} else if (systemActivated) {
			return "System Activated Awaiting Override...";
		} else {
			return "System Offline Engage Main Switch";
		}
	}
}
```

## Codigo Interactivo

```
Goal: have the isSolved() function return true
Status: DEPLOYED
Player Balance: 0.999944948 ETH
Player Wallet Address: 0x219EE75691596174612d5Fd4c675F06BA33630D3
Private Key: 0x8958eb8470de602ffbd72a80fd9fd7297b4621629ab71996d40f4d4105b127f4
Contract Address: 0x74dae0A0e456C8556525c7f16fB07CD9c25b2127
Block Time: 0
RPC URL: http://geth:8545
Chain ID: 31337
```

- **target address** es la dirección del contrato
- **geth** es la dirección IP de la máquina de instancia

## Solucion
Se utilizó `--legacy` debido a: Error: función no compatible: `eip1559`

```
$target = 0x74dae0A0e456C8556525c7f16fB07CD9c25b2127
$pkey = 0x8958eb8470de602ffbd72a80fd9fd7297b4621629ab71996d40f4d4105b127f4

cast send $target "engageMainSwitch()" --private-key $pkey --rpc-url http://10.10.154.205:8545 --legacy

cast send $target 'pressOverrideButton()' --private-key $pkey --rpc-url http://10.10.154.205:8545 --legacy
```