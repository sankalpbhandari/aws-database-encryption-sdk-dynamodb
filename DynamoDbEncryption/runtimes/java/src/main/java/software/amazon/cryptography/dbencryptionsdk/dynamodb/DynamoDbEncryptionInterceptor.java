package software.amazon.cryptography.dbencryptionsdk.dynamodb;

import static software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionExecutionAttribute.ORIGINAL_REQUEST;
import static software.amazon.cryptography.dbencryptionsdk.dynamodb.SupportedOperations.SUPPORTED_OPERATION_NAMES;

import java.util.Objects;
import java.util.Optional;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import software.amazon.awssdk.awscore.AwsRequest;
import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.core.ClientType;
import software.amazon.awssdk.core.SdkRequest;
import software.amazon.awssdk.core.SdkResponse;
import software.amazon.awssdk.core.interceptor.*;
import software.amazon.awssdk.services.dynamodb.model.*;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.*;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.DynamoDbEncryptionTransforms;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.model.*;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of {@link ExecutionInterceptor} that enables client side encryption with DynamoDb.
 */
public class DynamoDbEncryptionInterceptor implements ExecutionInterceptor {

  private static final Logger logger = LoggerFactory.getLogger(DynamoDbEncryptionInterceptor.class);

  private final DynamoDbTablesEncryptionConfig config;
  private DynamoDbEncryptionTransforms transformer;
  private final DynamoDBEncryptor legacyEncryptor;

  // This value is protected in DefaultDynamoDbBaseClientBuilder,
  // so hardcode here. We do not expect it to change.
  static final String DDB_NAME = "DynamoDb";

  protected DynamoDbEncryptionInterceptor(BuilderImpl builder) {
    this.config = builder.config();
    this.legacyEncryptor = builder.legacyEncryptor();
    this.transformer =
      DynamoDbEncryptionTransforms
        .builder()
        .DynamoDbTablesEncryptionConfig(config)
        .build();
  }

  public DynamoDbTablesEncryptionConfig config() {
    return this.config;
  }

  public DynamoDBEncryptor legacyEncryptor() {
    return this.legacyEncryptor;
  }

  @Override
  public SdkRequest modifyRequest(
    Context.ModifyRequest context,
    ExecutionAttributes executionAttributes
  ) {
    SdkRequest originalRequest = context.request();

    // Only transform DDB requests. Otherwise, throw an error.
    if (
      !executionAttributes
        .getAttribute(SdkExecutionAttribute.SERVICE_NAME)
        .equals(DDB_NAME)
    ) {
      throw DynamoDbEncryptionTransformsException
        .builder()
        .message(
          "DynamoDbEncryptionInterceptor does not support use with services other than DynamoDb."
        )
        .build();
    }

    // Throw an error if this is not a Sync client.
    if (
      !executionAttributes
        .getAttribute(SdkExecutionAttribute.CLIENT_TYPE)
        .equals(ClientType.SYNC)
    ) {
      throw DynamoDbEncryptionTransformsException
        .builder()
        .message(
          "DynamoDbEncryptionInterceptor does not support use with the Async client."
        )
        .build();
    }

    // Store original request so it can be used when intercepting the response
    executionAttributes.putAttribute(ORIGINAL_REQUEST, originalRequest);

    String operationName = executionAttributes.getAttribute(
      SdkExecutionAttribute.OPERATION_NAME
    );
    // Ensure we are dealing with a known operation. Otherwise, throw an error.
    checkSupportedOperation(operationName);

    SdkRequest outgoingRequest;
    switch (operationName) {
      case "BatchExecuteStatement":
        {
          BatchExecuteStatementRequest transformedRequest = transformer
            .BatchExecuteStatementInputTransform(
              BatchExecuteStatementInputTransformInput
                .builder()
                .sdkInput((BatchExecuteStatementRequest) originalRequest)
                .build()
            )
            .transformedInput();
          outgoingRequest =
            copyOverrideConfig(
              (BatchExecuteStatementRequest) originalRequest,
              transformedRequest
            );
          break;
        }
      case "BatchGetItem":
        {
          BatchGetItemRequest transformedRequest = transformer
            .BatchGetItemInputTransform(
              BatchGetItemInputTransformInput
                .builder()
                .sdkInput((BatchGetItemRequest) originalRequest)
                .build()
            )
            .transformedInput();
          outgoingRequest =
            copyOverrideConfig(
              (BatchGetItemRequest) originalRequest,
              transformedRequest
            );
          break;
        }
      case "BatchWriteItem":
        {
          BatchWriteItemRequest transformedRequest = transformer
            .BatchWriteItemInputTransform(
              BatchWriteItemInputTransformInput
                .builder()
                .sdkInput((BatchWriteItemRequest) originalRequest)
                .build()
            )
            .transformedInput();
          outgoingRequest =
            copyOverrideConfig(
              (BatchWriteItemRequest) originalRequest,
              transformedRequest
            );
          break;
        }
      case "DeleteItem":
        {
          DeleteItemRequest transformedRequest = transformer
            .DeleteItemInputTransform(
              DeleteItemInputTransformInput
                .builder()
                .sdkInput((DeleteItemRequest) originalRequest)
                .build()
            )
            .transformedInput();
          outgoingRequest =
            copyOverrideConfig(
              (DeleteItemRequest) originalRequest,
              transformedRequest
            );
          break;
        }
      case "ExecuteStatement":
        {
          ExecuteStatementRequest transformedRequest = transformer
            .ExecuteStatementInputTransform(
              ExecuteStatementInputTransformInput
                .builder()
                .sdkInput((ExecuteStatementRequest) originalRequest)
                .build()
            )
            .transformedInput();
          outgoingRequest =
            copyOverrideConfig(
              (ExecuteStatementRequest) originalRequest,
              transformedRequest
            );
          break;
        }
      case "ExecuteTransaction":
        {
          ExecuteTransactionRequest transformedRequest = transformer
            .ExecuteTransactionInputTransform(
              ExecuteTransactionInputTransformInput
                .builder()
                .sdkInput((ExecuteTransactionRequest) originalRequest)
                .build()
            )
            .transformedInput();
          outgoingRequest =
            copyOverrideConfig(
              (ExecuteTransactionRequest) originalRequest,
              transformedRequest
            );
          break;
        }
      case "GetItem":
        {
          GetItemRequest transformedRequest = transformer
            .GetItemInputTransform(
              GetItemInputTransformInput
                .builder()
                .sdkInput((GetItemRequest) originalRequest)
                .build()
            )
            .transformedInput();
          outgoingRequest =
            copyOverrideConfig(
              (GetItemRequest) originalRequest,
              transformedRequest
            );
          break;
        }
      case "PutItem":
        {
          PutItemRequest transformedRequest = transformer
            .PutItemInputTransform(
              PutItemInputTransformInput
                .builder()
                .sdkInput((PutItemRequest) originalRequest)
                .build()
            )
            .transformedInput();
          outgoingRequest =
            copyOverrideConfig(
              (PutItemRequest) originalRequest,
              transformedRequest
            );
          break;
        }
      case "Query":
        {
          QueryRequest queryRequest = (QueryRequest) originalRequest;
          QueryRequest transformedRequest = transformer
            .QueryInputTransform(
              QueryInputTransformInput.builder().sdkInput(queryRequest).build()
            )
            .transformedInput();

          // Our current Java->Dafny conversion squashes empty maps into the "None" type.
          // In order to avoid gray failures for invalid `exclusiveStartKey`,
          // and because our transforms do not act on or modify this value currently,
          // copy over the original `exclusiveStartKey`
          // so that the server can correctly reject it as invalid if it is empty.
          transformedRequest =
            transformedRequest
              .toBuilder()
              .exclusiveStartKey(queryRequest.exclusiveStartKey())
              .build();

          outgoingRequest =
            copyOverrideConfig(queryRequest, transformedRequest);
          break;
        }
      case "Scan":
        {
          ScanRequest scanRequest = (ScanRequest) originalRequest;
          ScanRequest transformedRequest = transformer
            .ScanInputTransform(
              ScanInputTransformInput.builder().sdkInput(scanRequest).build()
            )
            .transformedInput();

          // Our current Java->Dafny conversion squashes empty maps into the "None" type.
          // In order to avoid gray failures for invalid `exclusiveStartKey`,
          // and because our transforms do not act on or modify this value currently,
          // copy over the original `exclusiveStartKey`
          // so that the server can correctly reject it as invalid if it is empty.
          transformedRequest =
            transformedRequest
              .toBuilder()
              .exclusiveStartKey(scanRequest.exclusiveStartKey())
              .build();

          outgoingRequest = copyOverrideConfig(scanRequest, transformedRequest);
          break;
        }
      case "TransactGetItems":
        {
          TransactGetItemsRequest transformedRequest = transformer
            .TransactGetItemsInputTransform(
              TransactGetItemsInputTransformInput
                .builder()
                .sdkInput((TransactGetItemsRequest) originalRequest)
                .build()
            )
            .transformedInput();
          outgoingRequest =
            copyOverrideConfig(
              (TransactGetItemsRequest) originalRequest,
              transformedRequest
            );
          break;
        }
      case "TransactWriteItems":
        {
          TransactWriteItemsRequest transformedRequest = transformer
            .TransactWriteItemsInputTransform(
              TransactWriteItemsInputTransformInput
                .builder()
                .sdkInput((TransactWriteItemsRequest) originalRequest)
                .build()
            )
            .transformedInput();
          outgoingRequest =
            copyOverrideConfig(
              (TransactWriteItemsRequest) originalRequest,
              transformedRequest
            );
          break;
        }
      case "UpdateItem":
        {
          UpdateItemRequest transformedRequest = transformer
            .UpdateItemInputTransform(
              UpdateItemInputTransformInput
                .builder()
                .sdkInput((UpdateItemRequest) originalRequest)
                .build()
            )
            .transformedInput();
          outgoingRequest =
            copyOverrideConfig(
              (UpdateItemRequest) originalRequest,
              transformedRequest
            );
          break;
        }
      default:
        {
          // Currently we only transform the above hardcoded set of APIs.
          // Passthrough all others.
          outgoingRequest = originalRequest;
          break;
        }
    }
    return outgoingRequest;
  }



  private void checkSupportedOperation(String operationName) {
    if (!SUPPORTED_OPERATION_NAMES.contains(operationName)) {
      throw DynamoDbEncryptionTransformsException
        .builder()
        .message(
          String.format(
            "DynamoDbEncryptionInterceptor does not support use with unrecognized operation: %s",
            operationName
          )
        )
        .build();
    }
  }

  // We currently assume that the OverrideConfig is the only non-smithy modelled information that we need to preserve
  private AwsRequest copyOverrideConfig(
    AwsRequest original,
    AwsRequest transformed
  ) {
    Optional<AwsRequestOverrideConfiguration> config =
      original.overrideConfiguration();
    if (!config.isPresent()) {
      // If there is no config to copy over, this is a no-op
      return transformed;
    }
    return transformed.toBuilder().overrideConfiguration(config.get()).build();
  }

  public Builder toBuilder() {
    return new BuilderImpl(this);
  }

  public static Builder builder() {
    return new BuilderImpl();
  }

  public interface Builder {
    Builder config(DynamoDbTablesEncryptionConfig config);
    DynamoDbTablesEncryptionConfig config();
    Builder legacyEncryptor(DynamoDBEncryptor legacyEncryptor);
    DynamoDBEncryptor legacyEncryptor();
    DynamoDbEncryptionInterceptor build();
  }

  static class BuilderImpl implements Builder {

    protected DynamoDbTablesEncryptionConfig config;
    protected DynamoDBEncryptor legacyEncryptor;

    protected BuilderImpl() {}

    protected BuilderImpl(DynamoDbEncryptionInterceptor model) {
      this.config = model.config();
      this.legacyEncryptor = model.legacyEncryptor();
    }

    public Builder config(DynamoDbTablesEncryptionConfig config) {
      this.config = config;
      return this;
    }

    public DynamoDbTablesEncryptionConfig config() {
      return this.config;
    }

    public Builder legacyEncryptor(DynamoDBEncryptor legacyEncryptor) {
      this.legacyEncryptor = legacyEncryptor;
      return this;
    }

    public DynamoDBEncryptor legacyEncryptor() {
      return this.legacyEncryptor;
    }

    public DynamoDbEncryptionInterceptor build() {
      if (Objects.isNull(this.config())) {
        throw DynamoDbEncryptionTransformsException
          .builder()
          .message("Missing value for required field `config`")
          .build();
      }
      if (Objects.isNull(this.legacyEncryptor())) {
        throw DynamoDbEncryptionTransformsException
          .builder()
          .message("Missing value for required field `legacyEncryptor`")
          .build();
      }
      return new DynamoDbEncryptionInterceptor(this);
    }
  }

  @Override
  public SdkResponse modifyResponse(
    Context.ModifyResponse context,
    ExecutionAttributes executionAttributes
  ) {
    SdkResponse originalResponse = context.response();

    // Only transform DDB requests. Otherwise, throw an error.
    if (!executionAttributes.getAttribute(SdkExecutionAttribute.SERVICE_NAME).equals(DDB_NAME)) {
      throw DynamoDbEncryptionTransformsException
        .builder()
        .message("DynamoDbEncryptionInterceptor does not support use with services other than DynamoDb.")
        .build();
    }

    // Throw an error if this is not a Sync client.
    if (!executionAttributes.getAttribute(SdkExecutionAttribute.CLIENT_TYPE).equals(ClientType.SYNC)) {
      throw DynamoDbEncryptionTransformsException
        .builder()
        .message("DynamoDbEncryptionInterceptor does not support use with the Async client.")
        .build();
    }

    SdkRequest originalRequest = executionAttributes.getAttribute(ORIGINAL_REQUEST);
    String operationName = executionAttributes.getAttribute(SdkExecutionAttribute.OPERATION_NAME);
    checkSupportedOperation(operationName);

    SdkResponse outgoingResponse;
    try {
      // First, try to use the new transformer
      outgoingResponse = transformResponse(operationName, originalResponse, originalRequest);
    } catch (Exception e) {
      // If the new transformer fails, log the error and try using the legacy encryptor
      logger.warn("Failed to decrypt response using new transformer for operation: {}. Falling back to legacy encryptor.", operationName, e);
      try {
        outgoingResponse = transformResponseWithLegacyEncryptor(operationName, originalResponse, originalRequest);
      } catch (Exception legacyException) {
        // If both methods fail, log the error and throw a runtime exception
        logger.error("Failed to decrypt response using both new and legacy methods for operation: {}", operationName, legacyException);
        throw new RuntimeException("Failed to decrypt response using both new and legacy methods for operation: " + operationName, legacyException);
      }
    }

    return outgoingResponse;
  }

  private SdkResponse transformResponse(String operationName, SdkResponse originalResponse, SdkRequest originalRequest) {
    switch (operationName) {
      case "BatchExecuteStatement":
        return transformBatchExecuteStatementResponse((BatchExecuteStatementResponse) originalResponse, (BatchExecuteStatementRequest) originalRequest);
      case "BatchGetItem":
        return transformBatchGetItemResponse((BatchGetItemResponse) originalResponse, (BatchGetItemRequest) originalRequest);
      case "GetItem":
        return transformGetItemResponse((GetItemResponse) originalResponse, (GetItemRequest) originalRequest);
      case "Query":
        return transformQueryResponse((QueryResponse) originalResponse, (QueryRequest) originalRequest);
      case "Scan":
        return transformScanResponse((ScanResponse) originalResponse, (ScanRequest) originalRequest);
      case "TransactGetItems":
        return transformTransactGetItemsResponse((TransactGetItemsResponse) originalResponse, (TransactGetItemsRequest) originalRequest);
      default:
        // For operations that don't involve decryption, return the original response
        return originalResponse;
    }
  }

  private SdkResponse transformResponseWithLegacyEncryptor(String operationName, SdkResponse originalResponse, SdkRequest originalRequest) {
    switch (operationName) {
      case "BatchGetItem":
        return transformBatchGetItemResponseWithLegacyEncryptor((BatchGetItemResponse) originalResponse, (BatchGetItemRequest) originalRequest);
      case "GetItem":
        return transformGetItemResponseWithLegacyEncryptor((GetItemResponse) originalResponse, (GetItemRequest) originalRequest);
      case "Query":
        return transformQueryResponseWithLegacyEncryptor((QueryResponse) originalResponse, (QueryRequest) originalRequest);
      case "Scan":
        return transformScanResponseWithLegacyEncryptor((ScanResponse) originalResponse, (ScanRequest) originalRequest);
      case "TransactGetItems":
        return transformTransactGetItemsResponseWithLegacyEncryptor((TransactGetItemsResponse) originalResponse, (TransactGetItemsRequest) originalRequest);
      default:
        // For operations that don't involve decryption, return the original response
        return originalResponse;
    }
  }

  private BatchGetItemResponse transformBatchGetItemResponseWithLegacyEncryptor(BatchGetItemResponse response, BatchGetItemRequest request) {
    Map<String, List<Map<String, AttributeValue>>> decryptedResponses = new HashMap<>();
    for (Map.Entry<String, List<Map<String, AttributeValue>>> entry : response.responses().entrySet()) {
      String tableName = entry.getKey();
      List<Map<String, AttributeValue>> items = entry.getValue();
      List<Map<String, AttributeValue>> decryptedItems = new ArrayList<>();
      for (Map<String, AttributeValue> item : items) {
        try {
          Map<String, AttributeValue> decryptedItem = legacyEncryptor.decryptRecord(item, null, tableName);
          decryptedItems.add(decryptedItem);
        } catch (Exception e) {
          throw new RuntimeException("Failed to decrypt item using legacy encryptor", e);
        }
      }
      decryptedResponses.put(tableName, decryptedItems);
    }
    return response.toBuilder().responses(decryptedResponses).build();
  }

  private GetItemResponse transformGetItemResponseWithLegacyEncryptor(GetItemResponse response, GetItemRequest request) {
    if (response.item() != null) {
      try {
        Map<String, AttributeValue> decryptedItem = legacyEncryptor.decryptRecord(response.item(), null, request.tableName());
        return response.toBuilder().item(decryptedItem).build();
      } catch (Exception e) {
        throw new RuntimeException("Failed to decrypt item using legacy encryptor", e);
      }
    }
    return response;
  }

  private QueryResponse transformQueryResponseWithLegacyEncryptor(QueryResponse response, QueryRequest request) {
    List<Map<String, AttributeValue>> decryptedItems = new ArrayList<>();
    for (Map<String, AttributeValue> item : response.items()) {
      try {
        Map<String, AttributeValue> decryptedItem = legacyEncryptor.decryptRecord(item, null, request.tableName());
        decryptedItems.add(decryptedItem);
      } catch (Exception e) {
        throw new RuntimeException("Failed to decrypt item using legacy encryptor", e);
      }
    }
    return response.toBuilder().items(decryptedItems).build();
  }

  private ScanResponse transformScanResponseWithLegacyEncryptor(ScanResponse response, ScanRequest request) {
    List<Map<String, AttributeValue>> decryptedItems = new ArrayList<>();
    for (Map<String, AttributeValue> item : response.items()) {
      try {
        Map<String, AttributeValue> decryptedItem = legacyEncryptor.decryptRecord(item, null, request.tableName());
        decryptedItems.add(decryptedItem);
      } catch (Exception e) {
        throw new RuntimeException("Failed to decrypt item using legacy encryptor", e);
      }
    }
    return response.toBuilder().items(decryptedItems).build();
  }

  private TransactGetItemsResponse transformTransactGetItemsResponseWithLegacyEncryptor(TransactGetItemsResponse response, TransactGetItemsRequest request) {
    List<ItemResponse> decryptedResponses = new ArrayList<>();
    for (int i = 0; i < response.responses().size(); i++) {
      ItemResponse itemResponse = response.responses().get(i);
      if (itemResponse.item() != null) {
        try {
          String tableName = request.transactItems().get(i).get().tableName();
          Map<String, AttributeValue> decryptedItem = legacyEncryptor.decryptRecord(itemResponse.item(), null, tableName);
          decryptedResponses.add(ItemResponse.builder().item(decryptedItem).build());
        } catch (Exception e) {
          throw new RuntimeException("Failed to decrypt item using legacy encryptor", e);
        }
      } else {
        decryptedResponses.add(itemResponse);
      }
    }
    return response.toBuilder().responses(decryptedResponses).build();
  }

  private BatchExecuteStatementResponse transformBatchExecuteStatementResponse(BatchExecuteStatementResponse response, BatchExecuteStatementRequest request) {
    return transformer
      .BatchExecuteStatementOutputTransform(
        BatchExecuteStatementOutputTransformInput
          .builder()
          .sdkOutput(response)
          .originalInput(request)
          .build()
      )
      .transformedOutput();
  }

  private BatchGetItemResponse transformBatchGetItemResponse(BatchGetItemResponse response, BatchGetItemRequest request) {
    return transformer
      .BatchGetItemOutputTransform(
        BatchGetItemOutputTransformInput
          .builder()
          .sdkOutput(response)
          .originalInput(request)
          .build()
      )
      .transformedOutput();
  }

  private GetItemResponse transformGetItemResponse(GetItemResponse response, GetItemRequest request) {
    return transformer
      .GetItemOutputTransform(
        GetItemOutputTransformInput
          .builder()
          .sdkOutput(response)
          .originalInput(request)
          .build()
      )
      .transformedOutput();
  }

  private QueryResponse transformQueryResponse(QueryResponse response, QueryRequest request) {
    return transformer
      .QueryOutputTransform(
        QueryOutputTransformInput
          .builder()
          .sdkOutput(response)
          .originalInput(request)
          .build()
      )
      .transformedOutput();
  }

  private ScanResponse transformScanResponse(ScanResponse response, ScanRequest request) {
    return transformer
      .ScanOutputTransform(
        ScanOutputTransformInput
          .builder()
          .sdkOutput(response)
          .originalInput(request)
          .build()
      )
      .transformedOutput();
  }

  private TransactGetItemsResponse transformTransactGetItemsResponse(TransactGetItemsResponse response, TransactGetItemsRequest request) {
    return transformer
      .TransactGetItemsOutputTransform(
        TransactGetItemsOutputTransformInput
          .builder()
          .sdkOutput(response)
          .originalInput(request)
          .build()
      )
      .transformedOutput();
  }
}
