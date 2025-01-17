import bcrypt from "bcrypt";

/**
 * @name Bcrypt
 * @description É uma adaptação da biblioteca bcrypt
 * {@link https://www.npmjs.com/package/bcrypt}
 *
 *@author Michele Kopper
 */

export class Bcrypt {
  /**
   * @name generateHash()
   * @description Método responsável por gerar um hash
   * @param password Senha que será encriptografada
   * @returns Hash gerado
   * @example
   * const bcrypt = new Bcrypt();
   * const passwordHash = await bcrypt.generateHash(password);
   */

  // Embaralhar a nossa senha (criar o hash) => // $2a$10$..Z1P/ls25bYKpWYocayUuh/nmIPnAo2ScuEId7vBdBMNK/vnJGzS
  public async generateHash(password: string): Promise<string> {
    const hash = await bcrypt.hash(password, Number(process.env.BCRYPT_SALT));
    return hash;
  }



  
  // Verificar o nosso hash // senha123 === $2a$10$..Z1P/ls25bYKpWYocayUuh/nmIPnAo2ScuEId7vBdBMNK/vnJGzS => true
  public async verify(password: string, hash: string): Promise<boolean> {
    const isValid = await bcrypt.compare(password, hash);
    return isValid;
  }
}
