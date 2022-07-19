import { GraphQLObjectType } from "graphql";
import { IUser, IRegisterUserInput } from "./user.resolver.spec";
import bcrypt from "bcrypt";
import { ApolloError } from "apollo-server-express";
import { ExpressContext } from "apollo-server-express";
import { create_UUID, generateToken } from "../../lib/utilities";

let users: Array<IUser> = [];

export default {
  Query: {
    listUsers: () => users,
  },

  Mutation: {
    register: async (
      _: GraphQLObjectType,
      { registerUserInput }: IRegisterUserInput,
      { res }: ExpressContext
    ) => {
      const { password, username } = registerUserInput;
      if (users.some((e) => e.username === username)) {
        throw new ApolloError("Cet utilistaeur existe déjà");
      }
      const salt = await bcrypt.genSalt(10);
      const hashed = await bcrypt.hash(password, salt);
      const id = create_UUID(); //non utile avec une BDD bien sûr
      const roles = ["user"]; //rôle par défaut
      const permissions = ["read:any_account", "read:own_account"]; //permissions par défaut

      let newUser: IUser = {
        id,
        username,
        password: hashed,
        roles,
        permissions,
      };

      let token = generateToken({ username, id, roles, permissions });
      users = [...users, newUser];
      res.cookie("token", token, {
        secure: process.env.NODE_ENV === "production",
        httpOnly: true, //le httpOnly n'est pas accessible via du code JS, ça limite un peu les injection XSS (mais ce n'est pas infaillible comme précisé plus haut)
        maxAge: 1000 * 60 * 60 * 2, //2 heures
      });
      return { ...newUser, success: true };
    },
  },
};
