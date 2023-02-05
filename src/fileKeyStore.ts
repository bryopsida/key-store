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
