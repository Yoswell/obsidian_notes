# Obscurity - TKM 2025
El relé de anulación de la planta estaba gobernado por blockchain. Eso fue hasta que Flicker incorporó un apretón de manos de sabotaje dentro de la lógica de estado del contrato. Ahora, la maquinaria no responderá a menos que se vuelva a ejecutar la secuencia oculta. Los sensores están leyendo *Interruptor principal: ON*, pero nada se mueve. La bifurcación fantasma del contrato inteligente de Flicker recableó la verificación del estado, ocultando la anulación real detrás de dos llamadas en el orden correcto

> Nota: La máquina virtual tarda unos 4 minutos en iniciarse

## Solidity Code
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Challenge {
	string private secret = "THM{}";
	bool private unlock_flag = false;
	uint256 private code;
	
	string private hint_text;
	
	constructor(
		string memory flag, string memory challenge_hint,
		uint256 challenge_code) {
		secret = flag;
		code = challenge_code;
		hint_text = challenge_hint;
	}
	
	function hint() external view returns (string memory) {
		return hint_text;
	}
	
	function unlock(uint256 input) external returns (bool) {
		if (input == code) {
			unlock_flag = true;
			return true;
		}
	
		return false;
	}
	
	function isSolved() external view returns (bool) {
		return unlock_flag;
	}
	
	function getFlag() external view returns (string memory) {
		require(unlock_flag, "Challenge not solved yet");
		return secret;
	}
}
```

1. **target address** es la dirección del contrato
2. **geth** es la dirección IP de la máquina de instancia

## Solucion
Es necesario conocer el código para desbloquear la bandera. El código son los últimos 6 dígitos de la clave privada. Eso es posible, podemos ver las *ranuras*

Se utilizó `--legacy` debido a: Error: función no compatible: `eip1559`

```
$target = 0x74dae0A0e456C8556525c7f16fB07CD9c25b2127
$pkey = 0xf0405ec2170a2111a1a9144168a152baea149e82d400ee06dccc8a7bea86b1bb

string private secret = "THM{}";  => slot 0
bool private unlock_flag = false; => slot 1
uint256 private code;             => slot 2
string private hint_text;         => slot 3

cast storage $target 1 --rpc-url http://10.10.104.195:8545
0x00000000000001000
// No hay una flag aun en el slot 1

cast storage $target 2 --rpc-url http://10.10.104.195:8545
0x00000000000001a7a

print(0x1a7a)
6778
// En el slot 2 podemos recuperar el valor de la variable code

cast call $target 'unlock(uint256)' 6778 --rpc-url http://10.10.104.195:8545 --legacy
cast call $target 'isSolved()' --rpc-url http://10.10.104.195:8545 --legacy
cast call $target 'getFlag()' --rpc-url http://10.10.104.195:8545

```