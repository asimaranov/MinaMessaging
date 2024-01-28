import { Message, MessagingZkApp, MerkleWitness8, SentMessageEvent } from './messaging';
import { PrivateKey, PublicKey, Mina, AccountUpdate, MerkleTree, Field, Poseidon, UInt64 } from 'o1js';

describe('sudoku', () => {
  let zkApp: MessagingZkApp,
    zkAppPrivateKey: PrivateKey,
    zkAppAddress: PublicKey,
    users: { publicKey: PublicKey; privateKey: PrivateKey; }[],
    sender: PublicKey,
    senderKey: PrivateKey;

  beforeEach(async () => {
    let Local = Mina.LocalBlockchain({ proofsEnabled: false });
    Mina.setActiveInstance(Local);
    sender = Local.testAccounts[0].publicKey;
    senderKey = Local.testAccounts[0].privateKey;
    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new MessagingZkApp(zkAppAddress);
    users = Local.testAccounts.slice(1);
  });

  it('Check not whitelisted user can`t send message', async () => {
    await deploy(zkApp, zkAppPrivateKey, sender, senderKey);

    const tree = new MerkleTree(8);

    let tx = await Mina.transaction(sender, () => {
      let zkApp = new MessagingZkApp(zkAppAddress);

      zkApp.store(tree.getRoot());
    });
    await tx.prove();
    await tx.sign([senderKey]).send();

    await expect(async () => {
      let tx2 = await Mina.transaction(users[0].publicKey, () => {
        let zkApp = new MessagingZkApp(zkAppAddress);

        const withness = new MerkleWitness8(tree.getWitness(0n));

        zkApp.sendMessage(new Message({ content: Field.from(0) }), withness);
      });
      await tx2.prove();
      await tx2.sign([users[0].privateKey]).send();
    }).rejects.toThrow(/Not whitelisted/);
  });

  it('Check allowed user can`t send incorrect message', async () => {
    await deploy(zkApp, zkAppPrivateKey, sender, senderKey);

    const tree = new MerkleTree(8);

    const leaf = Poseidon.hash(users[0].publicKey.toFields());
    const leafIndex = 0n;

    tree.setLeaf(leafIndex, leaf);

    let tx = await Mina.transaction(sender, () => {
      let zkApp = new MessagingZkApp(zkAppAddress);

      zkApp.store(tree.getRoot());
    });
    await tx.prove();
    await tx.sign([senderKey]).send();

    const INCORRECT_FLAGS_BY_CONDITIONS = [[
      0b110000,
      0b101000,
      0b100100,
      0b100010,
      0b100001,
    ],
    [
      0b010000,
    ],
    [
      0b000110,
      0b000101,
      0b000111,
    ],
    ];

    for (let conditionId = 0; conditionId < INCORRECT_FLAGS_BY_CONDITIONS.length; conditionId++) {
      INCORRECT_FLAGS_BY_CONDITIONS[conditionId].map(async flags => {
        await expect(async () => {
          let tx2 = await Mina.transaction(users[0].publicKey, () => {
            let zkApp = new MessagingZkApp(zkAppAddress);

            const withness = new MerkleWitness8(tree.getWitness(leafIndex));

            zkApp.sendMessage(new Message({ content: Field.from(flags) }), withness);
          });
          await tx2.prove();
          await tx2.sign([users[0].privateKey]).send();
        }).rejects.toThrow(`Condition ${conditionId + 1} failed`);
      })
    }
  });

  it('Check allowed user can send correct message', async () => {
    await deploy(zkApp, zkAppPrivateKey, sender, senderKey);

    const tree = new MerkleTree(8);

    const leaf = Poseidon.hash(users[0].publicKey.toFields());
    const leafIndex = 0n;

    tree.setLeaf(leafIndex, leaf);

    let tx = await Mina.transaction(sender, () => {
      let zkApp = new MessagingZkApp(zkAppAddress);

      zkApp.store(tree.getRoot());
    });
    await tx.prove();
    await tx.sign([senderKey]).send();

    const CORRECT_MESSAGE = Field.from(0b1111111100000000001111111111111000_011100);

    zkApp.sentMessagesNum.getAndRequireEquals().equals(UInt64.from(0)).assertTrue("Incorrect sent messages num");

    let tx2 = await Mina.transaction(users[0].publicKey, () => {
      let zkApp = new MessagingZkApp(zkAppAddress);

      const withness = new MerkleWitness8(tree.getWitness(leafIndex));

      zkApp.sendMessage(new Message({ content: Field.from(CORRECT_MESSAGE) }), withness);
    });
    await tx2.prove();
    await tx2.sign([users[0].privateKey]).send();

    zkApp.sentMessagesNum.getAndRequireEquals().equals(UInt64.from(1)).assertTrue("Incorrect sent messages num");

    let events = await zkApp.fetchEvents();

    const messageSent = events.find(x => x.type == 'messageSent')!;
    expect(messageSent.type).toEqual('messageSent');

    (messageSent.event.data as unknown as SentMessageEvent).sender.assertEquals(users[0].publicKey);
    (messageSent.event.data as unknown as SentMessageEvent).content.assertEquals(CORRECT_MESSAGE);
  });

  it('Check allowed user can`t send correct message twice', async () => {
    await deploy(zkApp, zkAppPrivateKey, sender, senderKey);

    const tree = new MerkleTree(8);

    const leaf = Poseidon.hash(users[0].publicKey.toFields());
    const leafIndex = 0n;

    tree.setLeaf(leafIndex, leaf);

    let tx = await Mina.transaction(sender, () => {
      let zkApp = new MessagingZkApp(zkAppAddress);

      zkApp.store(tree.getRoot());
    });
    await tx.prove();
    await tx.sign([senderKey]).send();

    const CORRECT_MESSAGE = Field.from(0b1111111100000000001111111111111000_011100);

    let tx2 = await Mina.transaction(users[0].publicKey, () => {
      let zkApp = new MessagingZkApp(zkAppAddress);

      const withness = new MerkleWitness8(tree.getWitness(leafIndex));

      zkApp.sendMessage(new Message({ content: Field.from(CORRECT_MESSAGE) }), withness);
    });
    await tx2.prove();
    await tx2.sign([users[0].privateKey]).send();

    await expect(async () => {
      let tx3 = await Mina.transaction(users[0].publicKey, () => {
        let zkApp = new MessagingZkApp(zkAppAddress);

        const withness = new MerkleWitness8(tree.getWitness(leafIndex));

        zkApp.sendMessage(new Message({ content: Field.from(CORRECT_MESSAGE) }), withness);
      });
      await tx3.prove();
      await tx3.sign([users[0].privateKey]).send();
    }).rejects.toThrow(`Not whitelisted`);
  });

  async function deploy(
    zkApp: MessagingZkApp,
    zkAppPrivateKey: PrivateKey,
    sender: PublicKey,
    senderKey: PrivateKey
  ) {
    let tx = await Mina.transaction(sender, () => {
      AccountUpdate.fundNewAccount(sender);
      zkApp.deploy();
    });
    await tx.prove();
    await tx.sign([zkAppPrivateKey, senderKey]).send();
  }
});