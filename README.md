# Key-Store

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=bryopsida_key-store&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=bryopsida_key-store) [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=bryopsida_key-store&metric=coverage)](https://sonarcloud.io/summary/new_code?id=bryopsida_key-store) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=bryopsida_key-store&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=bryopsida_key-store) [![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=bryopsida_key-store&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=bryopsida_key-store) [![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=bryopsida_key-store&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=bryopsida_key-store) [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=bryopsida_key-store&metric=bugs)](https://sonarcloud.io/summary/new_code?id=bryopsida_key-store)

## What is this?

This is a typescript library that can be used to create a key store for managing root and data encryption keys. A basic file store key store is included but it can also be extended to persist to a shared store such as redis.
What problem does this solve? This was intiailly created as part of a data munging project in which I needed to be able to dynamically encrypt credentials and share them across a distributed system using redis.

### How do I use it?

To create your own store extend from the BaseKeyStore and implement the required key slot functions. For example:

```typescript
import { writeFile, mkdir, access, readFile, unlink, rm } from 'fs/promises'
import { resolveHome } from './resolve.js'
import {
  BaseKeyStore,
  IKeyStoreContextProvider,
  IKeyStoreValueProvider,
} from './baseKeyStore'

/**
 * A implementation of BaseKeyStore that stores the sealed
 * keys into a desiginated spot in the file system, consumers
 * of the class supply providers that give the password, salt
 * and context to use for AAED
 */
export class FileKeyStore extends BaseKeyStore {
  private readonly keyStorePath: string

  /**
   *
   * @param {string} keyStorePath path to the folder where keys will be saved
   * @param {IKeyStoreValueProvider} keyStorePasswordProvider provide the password used to seal keys
   * @param {IKeyStoreValueProvider} keyStoreSaltProvider provide the salt used to seal keys
   * @param {IKeyStoreContextProvider} keyStoreContextProvider provider that will give the appropriate context based on key id
   */
  constructor(
    keyStorePath: string,
    keyStorePasswordProvider: IKeyStoreValueProvider,
    keyStoreSaltProvider: IKeyStoreValueProvider,
    keyStoreContextProvider: IKeyStoreContextProvider
  ) {
    super(
      keyStorePasswordProvider,
      keyStoreSaltProvider,
      keyStoreContextProvider
    )
    this.keyStorePath = resolveHome(keyStorePath)
  }

  /**
   * @Inheritdoc
   */
  protected hasKeyInSlot(keySlot: string): Promise<boolean> {
    return access(this.keyStorePath + '/' + keySlot)
      .then(() => true)
      .catch(() => false)
  }

  private async createKeyStoreDirIfNotExists(): Promise<void> {
    await access(this.keyStorePath).catch(async () => {
      await mkdir(this.keyStorePath, { recursive: true })
    })
  }

  /**
   * @Inheritdoc
   */
  protected async putKeyInSlot(keySlot: string, key: Buffer): Promise<void> {
    await this.createKeyStoreDirIfNotExists()
    await writeFile(this.keyStorePath + '/' + keySlot, key)
  }

  /**
   * @Inheritdoc
   */
  protected async getKeyInSlot(keySlot: string): Promise<Buffer> {
    return readFile(this.keyStorePath + '/' + keySlot)
  }

  /**
   * @Inheritdoc
   */
  protected async deleteKeySlot(keySlot: string): Promise<void> {
    await unlink(this.keyStorePath + '/' + keySlot)
  }

  /**
   * @Inheritdoc
   */
  protected async clearKeySlots(): Promise<void> {
    await rm(this.keyStorePath, { recursive: true, force: true, maxRetries: 3 })
  }

  /**
   * @Inheritdoc
   */
  async close(): Promise<void> {
    // nothing to do
  }
}
```

You can then use the store like this (snippet from a test):

```typescript
const storeDir = tmpdir()
const key = randomBytes(32)
const salt = randomBytes(16)
const context = randomBytes(32)

// create a keystore
const keystore = new FileKeyStore(
  storeDir + '/keystore',
  () => Promise.resolve(key),
  () => Promise.resolve(salt),
  () => Promise.resolve(context)
)

// create random data to act as key store
const dek = randomBytes(32)
const id = randomUUID()

// save it
await keystore.saveSealedDataEncKey(id, dek)

// ask for it back
const fetchedDek = await keystore.fetchSealedDataEncKey(id)

// should be the same
expect(fetchedDek).toEqual(dek)
```
