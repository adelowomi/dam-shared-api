import { Injectable } from '@nestjs/common';
import { FetchService } from 'nestjs-fetch';

@Injectable()
export class CustomFetchService {
  private readonly _fetchService: FetchService;
  public _headers: Record<string, string>;
  constructor(private fetchService: FetchService) {
    this._fetchService = fetchService;
  }

  public init(headers: Record<string, string>) {
    this._headers = headers;
  }

  // use arrow function to bind this to the class
  public post = async <T>(
    url: string,
    data: any,
  ): Promise<CustomFetchResponse<T>> => {
    const response = await this._fetchService.post(url, {
      body: JSON.stringify(data),
      headers: {
        'Content-Type': 'application/json',
        ...this._headers,
      },
    });

    if (!response.ok) {
      return new CustomFetchResponse<T>(response.status, response.statusText);
    }
    const result = await response.json();
    return new CustomFetchResponse<T>(
      response.status,
      response.statusText,
      result,
    );
  };

  public get = async <T>(
    url: string,
    queryParams?: Record<string, string>,
  ): Promise<CustomFetchResponse<T>> => {
    console.log('🚀 ~ CustomFetchService ~ queryParams:', queryParams);
    const queryString = queryParams
      ? '?' + new URLSearchParams(queryParams).toString()
      : '';
    console.log('🚀 ~ CustomFetchService ~ queryString:', queryString);
    console.log('🚀 ~ CustomFetchService ~ fetchService:', this._fetchService);
    console.log('🚀 ~ CustomFetchService ~ headers:', this._headers);
    const response = await this._fetchService.get(url + queryString, {
      headers: this._headers,
    });
    console.log('🚀 ~ CustomFetchService ~ response:', response);

    if (!response.ok) {
      return new CustomFetchResponse<T>(response.status, response.statusText);
    }
    const result = await response.json();
    console.log('🚀 ~ CustomFetchService ~ result:', result);
    return new CustomFetchResponse<T>(
      response.status,
      response.statusText,
      result,
    );
  };
}

export class CustomFetchResponse<T> {
  constructor(
    public readonly status: number,
    public readonly message?: string,
    public readonly data?: T,
  ) {}
}
