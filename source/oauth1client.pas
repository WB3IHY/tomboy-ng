unit oauth1client;

{  Copyright (C) 2026

    License:
    This code is licensed under MIT License, see the file License.txt
    or https://spdx.org/licenses/MIT.html  SPDX short identifier: MIT

  ------------------

  OAuth 1.0a client-side request signing (RFC 5849), used by transwebsync to
  talk to any Tomboy Web Sync API 1.0 compatible server (Puddle, Grauphel,
  Rainy). Deliberately small and self contained - the protocol is frozen and
  well understood, not worth an external dependency for.

  Every client in this ecosystem (Tomdroid's signpost-based consumer, desktop
  Tomboy's WebSyncService addin, and the server side confirmed while building
  Puddle) hardcodes the same consumer key/secret pair - there is no per-app
  registration system here, see OAuthConsumerKey/Secret below.
}

{$mode objfpc}{$H+}

interface

uses
    Classes, SysUtils;

const
    OAuthConsumerKey = 'anyone';
    OAuthConsumerSecret = 'anyone';

type

    { TOAuthParams - an ordered list of "name=value" pairs (unencoded) to be
      signed. Add every parameter that must be part of the signature -
      oauth_callback, oauth_verifier, and any extra query parameters (eg
      include_notes) - before calling OAuthSignRequest, which itself adds
      the standard oauth_consumer_key/nonce/timestamp/signature_method/
      version/token parameters and finally oauth_signature. }
    TOAuthParams = class(TStringList)
    public
        procedure AddParam(const AName, AValue: string);
    end;

    { RFC 3986 unreserved-character percent-encoding (RFC 5849 section 3.6) -
      NOT the same as a generic URL-encoder, which leaves extra characters
      (eg '!', '*', ''') unescaped. Operates byte-by-byte, so multi-byte
      UTF-8 characters come out correctly as multiple %XX triples. }
function OAuthPercentEncode(const S: string): string;

function OAuthNonce: string;
function OAuthTimestamp: string;

    { Adds the standard oauth_* parameters (including oauth_token, if
      TokenValue is not empty) to Params, then computes and appends
      oauth_signature. Params may already contain other signed parameters
      (oauth_callback, oauth_verifier, extra query params) - add those
      before calling this. }
procedure OAuthSignRequest(const HttpMethod, URL: string; Params: TOAuthParams;
    const TokenValue, TokenSecret: string);

    { Builds a valid Authorization header VALUE (without the leading
      "Authorization: ") from a Params list that already includes
      oauth_signature (ie, call after OAuthSignRequest). }
function OAuthAuthHeader(Params: TOAuthParams): string;

    { Builds a query string (starting with '?') from Params. }
function OAuthQueryString(Params: TOAuthParams): string;

implementation

uses DateUtils, HMAC, base64;

{ TOAuthParams }

procedure TOAuthParams.AddParam(const AName, AValue: string);
begin
    Add(AName + '=' + AValue);
end;

function OAuthPercentEncode(const S: string): string;
const
    Unreserved = ['A'..'Z', 'a'..'z', '0'..'9', '-', '.', '_', '~'];
var
    I: integer;
begin
    Result := '';
    for I := 1 to Length(S) do
        if S[I] in Unreserved then
            Result := Result + S[I]
        else
            Result := Result + '%' + IntToHex(Ord(S[I]), 2);
end;

function OAuthTimestamp: string;
begin
    Result := IntToStr(SecondsBetween(Now, EncodeDate(1970, 1, 1)));
end;

function OAuthNonce: string;
var
    GUID: TGUID;
begin
    CreateGUID(GUID);
    Result := copy(GUIDToString(GUID), 2, 36);      // strip the wrapping { }
end;

    { Sorts (a copy of) Params by percent-encoded key then value, ordinal,
      per RFC 5849 3.4.1.3.2, and returns them joined as key=value&key=value }
function NormalizedParamString(Params: TOAuthParams): string;
var
    Encoded: TStringList;
    I: integer;
begin
    Encoded := TStringList.Create;
    try
        for I := 0 to Params.Count - 1 do
            Encoded.Add(OAuthPercentEncode(Params.Names[I]) + '='
                + OAuthPercentEncode(Params.ValueFromIndex[I]));
        Encoded.Sort;      // default ordinal string compare - fine, keys have no duplicates here
        Result := '';
        for I := 0 to Encoded.Count - 1 do begin
            if I > 0 then Result := Result + '&';
            Result := Result + Encoded[I];
        end;
    finally
        Encoded.Free;
    end;
end;

procedure OAuthSignRequest(const HttpMethod, URL: string; Params: TOAuthParams;
    const TokenValue, TokenSecret: string);
var
    BaseString, SigningKey, Signature: string;
begin
    Params.AddParam('oauth_consumer_key', OAuthConsumerKey);
    Params.AddParam('oauth_signature_method', 'HMAC-SHA1');
    Params.AddParam('oauth_timestamp', OAuthTimestamp);
    Params.AddParam('oauth_nonce', OAuthNonce);
    Params.AddParam('oauth_version', '1.0');
    if TokenValue <> '' then
        Params.AddParam('oauth_token', TokenValue);

    BaseString := UpperCase(HttpMethod) + '&' + OAuthPercentEncode(URL) + '&'
        + OAuthPercentEncode(NormalizedParamString(Params));

    // Signing key is consumer-secret & token-secret, NOT consumer-key & token-secret -
    // note the consumer key and secret happen to be the same literal string
    // ("anyone") in this ecosystem, which is easy to confuse with each other.
    SigningKey := OAuthPercentEncode(OAuthConsumerSecret) + '&' + OAuthPercentEncode(TokenSecret);
    Signature := EncodeStringBase64(HMACSHA1(SigningKey, BaseString));

    Params.AddParam('oauth_signature', Signature);
end;

function OAuthAuthHeader(Params: TOAuthParams): string;
var
    I: integer;
begin
    Result := 'OAuth ';
    for I := 0 to Params.Count - 1 do begin
        if I > 0 then Result := Result + ', ';
        Result := Result + OAuthPercentEncode(Params.Names[I]) + '="'
            + OAuthPercentEncode(Params.ValueFromIndex[I]) + '"';
    end;
end;

function OAuthQueryString(Params: TOAuthParams): string;
var
    I: integer;
begin
    Result := '';
    for I := 0 to Params.Count - 1 do begin
        if I = 0 then Result := '?' else Result := Result + '&';
        Result := Result + OAuthPercentEncode(Params.Names[I]) + '='
            + OAuthPercentEncode(Params.ValueFromIndex[I]);
    end;
end;

end.
