import { Query, Params } from "@feathersjs/feathers";
import { NotAuthenticated, BadRequest } from "@feathersjs/errors";
import {
  AuthenticationBaseStrategy,
  AuthenticationResult
} from "@feathersjs/authentication";

export class RefreshTokenStrategy extends AuthenticationBaseStrategy {
  verifyConfiguration() {
    const config = this.configuration;
    ["entity", "service", "clientIdField", "userIdField"].forEach(p => {
      if (typeof config[p] !== "string") {
        throw new Error(
          `'${this.name}' authentication strategy requires a '${p}' setting`
        );
      }
    });
  }
  get configuration() {
    const authConfig = this.authentication!.configuration;
    const config = super.configuration || {};
    return {
      errorMessage: "Invalid login",
      ...config,
      authConfig
    };
  }

  getEntityQuery(query: Query, _params: Params) {
    return {
      $limit: 1,
      ...query
    };
  }

  async findEntity(data: any, params: Params) {
    const { entityService } = this;
    const { entity, clientIdField } = this.configuration;
    const query = this.getEntityQuery(
      {
        [entity]: data[entity]
      },
      params
    );
    const result = await entityService.find({ query });
    if (result.total === 0) {
      throw new NotAuthenticated();
    }
    return result.data[0];
  }
  async getAuthEntity(id: any, params: Params) {
    const { service } = this.configuration.authConfig;
    const entityService = this.app!.service(service);

    try {
      const query = await this.getEntityQuery({
                [userIdField]: id
            }, params);

      const findParams = Object.assign({}, params, { query });
      const result = await entityService.find(findParams);
      const list = Array.isArray(result) ? result : result.data;

      const [ u ] = list;

      return u
    } catch (e) {
      throw new NotAuthenticated();
    }
  }

  async authenticate(
    authenticationRequest: AuthenticationResult,
    params: Params
  ) {
    const { entity, clientIdField, authConfig } = this.configuration;
    const response = {};
    [entity].forEach(p => {
      if (p in authenticationRequest) return;
      throw new BadRequest(`${p} is missing from request`);
    });

    const token = await this.findEntity(
      {
        [entity]: authenticationRequest[entity],
        [clientIdField]: authenticationRequest[clientIdField]
      },
      params
    );

    const accessToken = await this.app!.service(
      "authentication"
    ).createAccessToken({ sub: token[clientIdField] });

    return Object.assign({}, response, {
      authentication: { strategy: this.name },
      accessToken,
      'userId': token[clientIdField],
      [entity]: token[entity]
    });
  }
}
