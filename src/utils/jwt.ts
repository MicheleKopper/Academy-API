import jwt from "jsonwebtoken";
import { AuthStudent } from "../types/student.types";

// jwt.sign(dado, palavraSecreta, configs) - Gera um token
// jwt.decode() - Decodifica o token
// jwt.verify() - Verifica e decodifica o token

// IMPLEMENTAÇÃO
export class JWT {
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

  // Verificar o token
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