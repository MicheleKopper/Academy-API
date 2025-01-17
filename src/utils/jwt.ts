import jwt from "jsonwebtoken";
import { AuthStudent } from "../types/student.types";

// jwt.sign(dado, palavraSecreta, configs) - Gera um token
// jwt.decode() - Decodifica o token
// jwt.verify() - Verifica e decodifica o token

/**
 * @class JWT - adaptação da biblioteca jwt
 * @see Documentação {@link https://jwt.io/}
 */

// IMPLEMENTAÇÃO
export class JWT {
  /**
   * Método para gerar um token a partir de um estudante fornecido
   * @param data Objeto no formato **AuthStudent**
   * @see {@link AuthStudent}
   * @returns Token assinado no formato jwt
   *
   * @example
   * import { JWT } from "../utils/jwt";
   *
   * const jwt = new JWT();
   * const token = jwt.genereteToken(payload);
   */

  // Gerar o token - sign in
  public genereteToken(data: AuthStudent): string {
    if (!process.env.JWT_SECRET) {
      throw new Error("Secret not defined");
    }

    const token = jwt.sign(data, process.env.JWT_SECRET, {
      algorithm: "HS256",
      expiresIn: process.env.JWT_EXPIRES_IN,
    });

    return token;
  }

  /**
   * Método para verificar e decodificar o token recebido
   * @param token string recebida para verificação
   * @returns Estudante em caso de sucesso
   * @returns null em caso de erro
   *
   * @example
   * import { JWT } from "../../utils/jwt";
   * 
   * const jwt = new JWT();
   * const studentDecoded = jwt.verifyToken(token);
   */
  public verifyToken(token: string): AuthStudent | null {
    try {
      if (!process.env.JWT_SECRET) {
        throw new Error("Secret not defined");
      }
      // Token não assinado = quebra
      const data = jwt.verify(token, process.env.JWT_SECRET) as AuthStudent;
      return data;
    } catch {
      return null;
    }
  }
}
