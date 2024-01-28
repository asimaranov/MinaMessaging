import {
  Field,
  SmartContract,
  method,
  Bool,
  state,
  State,
  Poseidon,
  Struct,
  Provable,
  MerkleWitness,
  PublicKey,
  AccountUpdate,
  UInt64,
} from 'o1js';
import { Gadgets } from 'o1js/dist/node/lib/gadgets/gadgets';

export { Message, MessagingZkApp };

const MESSAGE_MAX_LENGTH = 254;

class Message extends Struct({
  content: Field,
}) {
  check() {
    Provable.if(
      Gadgets.and(this.content, Field.from(0b100000), MESSAGE_MAX_LENGTH).greaterThan(0), 
      Gadgets.and(this.content, Field.from(0b011111), MESSAGE_MAX_LENGTH).equals(0), 
      Bool(true)
    ).assertTrue("Condition 1 failed");

    Provable.if(
      Gadgets.and(this.content, Field.from(0b010000), MESSAGE_MAX_LENGTH).greaterThan(0), 
      Gadgets.and(this.content, Field.from(0b001000), MESSAGE_MAX_LENGTH).greaterThan(0), 
      Bool(true)
    ).assertTrue("Condition 2 failed");

    Provable.if(
      Gadgets.and(this.content, Field.from(0b000100), MESSAGE_MAX_LENGTH).greaterThan(0), 
      Gadgets.and(this.content, Field.from(0b000011), MESSAGE_MAX_LENGTH).equals(0), 
      Bool(true)
    ).assertTrue("Condition 3 failed");
  }
}

export class SentMessageEvent extends Struct({
  sender: PublicKey,
  content: Field,
}) {}

export class MerkleWitness8 extends MerkleWitness(8) {}

class MessagingZkApp extends SmartContract {
  @state(PublicKey) admin = State<PublicKey>();
  @state(Field) allowlistRoot = State<Field>();
  @state(Field) sentMessagesNum = State<UInt64>();

  events = { messageSent: SentMessageEvent };

  @method store(newAllowlistRoot: Field) {
    this.allowlistRoot.getAndRequireEquals().assertEquals(Field.empty());
    this.allowlistRoot.set(newAllowlistRoot);
  }

  @method sendMessage(message: Message, witness: MerkleWitness8) {
    AccountUpdate.createSigned(this.sender);
    
    message.check();

    const calculatedAllowlistRoot = witness.calculateRoot(Poseidon.hash(this.sender.toFields()));
    calculatedAllowlistRoot.assertEquals(this.allowlistRoot.getAndRequireEquals(), "Not whitelisted");

    const nullifiedRoot = witness.calculateRoot(Poseidon.hash(PublicKey.empty().toFields()));
    this.allowlistRoot.set(nullifiedRoot);

    this.emitEvent('messageSent', new SentMessageEvent({
      sender: this.sender,
      content: message.content
    }));

    this.sentMessagesNum.set(this.sentMessagesNum.getAndRequireEquals().add(1));
  }
}