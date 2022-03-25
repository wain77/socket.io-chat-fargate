import { DynamoDB } from 'aws-sdk';
import { hash, compare } from 'bcrypt';
import { REGION, DYNAMODB_ENDPOINT, ENV_NAME } from './config';

class User {
  constructor() {
    this.saltRounds = 10;
    this.dynamoDB = new DynamoDB.DocumentClient({
      region: REGION,
      endpoint: DYNAMODB_ENDPOINT
    });
    this.tableName = `${ENV_NAME}_Users`;
  }
  /**
    * Get a user by their username
    *
    *   @param {string} username - Username of the user
    *   @param {string} password - The user's password
  **/
  async fetchByUsername(username) {
    let details = null;

    try {
      details = await this.dynamoDB.get({
        TableName: this.tableName,
        Key: {
          username: username
        }
      }).promise();
    } catch (e) {
      console.error(e);

      throw new Error('Failed to lookup user by username');
    }

    return details.Item;
  }
  /**
    * Create a new user with given details
    *
    *   @param {object} details
    *   @param {string} details.username
    *   @param {string} details.email
    *   @param {string} details.password
  **/
  async create(details) {
    const existingAccount = await this.fetchByUsername(details.username);

    if (existingAccount) {
      throw new Error('That username is taken already.');
    }

    let passwordHash = null;

    try {
      passwordHash = await hash(details.password, this.saltRounds);
    } catch (e) {
      console.error(e);
      throw e;
    }

    try {
      await this.dynamoDB.put({
        TableName: this.tableName,
        Item: {
          username: details.username,
          email: details.email,
          passwordHash: passwordHash
        }
      }).promise();
    } catch (e) {
      console.error(e);

      throw new Error('Failed to insert new user in database');
    }

    return 'Success';
  }
  /**
    * Authenticate a user who submits their username and plaintext password
    *
    *   @param {object} details
    *   @param {string} details.username
    *   @param {string} details.password
  **/
  async authenticate(details) {
    const account = await this.fetchByUsername(details.username);

    if (!account) {
      throw new Error('No matching account found');
    }

    const passed = await compare(details.password, account.passwordHash);

    if (passed) {
      return {
        username: account.username,
        email: account.email
      };
    }

    return false;
  }
}
export default new User();




