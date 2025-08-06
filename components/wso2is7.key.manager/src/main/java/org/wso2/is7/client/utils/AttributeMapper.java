/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.is7.client.utils;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.kmclient.KeyManagerClientException;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.charon3.core.attributes.Attribute;
import org.wso2.charon3.core.attributes.ComplexAttribute;
import org.wso2.charon3.core.attributes.MultiValuedAttribute;
import org.wso2.charon3.core.attributes.SimpleAttribute;
import org.wso2.charon3.core.config.SCIMUserSchemaExtensionBuilder;
import org.wso2.charon3.core.encoder.JSONDecoder;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.objects.AbstractSCIMObject;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.schema.AttributeSchema;
import org.wso2.charon3.core.schema.SCIMAttributeSchema;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.schema.SCIMDefinitions;
import org.wso2.charon3.core.schema.SCIMResourceTypeSchema;
import org.wso2.charon3.core.utils.AttributeUtil;
import org.wso2.is7.client.WSO2ISConstants;
import org.wso2.is7.client.model.WSO2IS7SCIMSchemasClient;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.wso2.charon3.core.schema.SCIMSchemaDefinitions.SCIM_USER_SCHEMA;
import static org.wso2.is7.client.WSO2ISConstants.SCIM2_CORE_SCHEMA;
import static org.wso2.is7.client.WSO2ISConstants.SCIM2_ENTERPRISE_SCHEMA;
import static org.wso2.is7.client.WSO2ISConstants.SCIM2_SYSTEM_SCHEMA_URI;
import static org.wso2.is7.client.WSO2ISConstants.SCIM2_USER_SCHEMA;

/**
 * Contains methods related to SCIM attribute mapping.
 * Copied from
 * https://raw.githubusercontent.com/wso2-extensions/identity-inbound-provisioning-scim2/master/components/org.wso2.carbon.identity.scim2.common/src/main/java/org/wso2/carbon/identity/scim2/common/utils/AttributeMapper.java
 * to avoid dependency on identity-inbound-provisioning-scim2 module.
 */
public class AttributeMapper {

    private static final String ADVANCED_ATTRIBUTE_IDENTIFIER = "#";
    private static final String SCIM_COMPLEX_MULTIVALUED_ATTRIBUTE_SUPPORT_ENABLED = "SCIM2" +
            ".ComplexMultiValuedAttributeSupportEnabled";

    /**
     * Get user claims from the given SCIM object string.
     * @deprecated This method is deprecated and will be removed in future versions.
     *
     * @param scimUserObjectString      SCIM 2.0 Payload of a user info.
     * @return                          A map that contains the SCIM URI and the value of the claim.
     * @throws APIManagementException   If an error occurs while decoding the SCIM object, or getting the claims.
     */
    @Deprecated
    public static Map<String, String> getUserClaims(String scimUserObjectString) throws APIManagementException {

        return getUserClaims(scimUserObjectString, null, null, null, null);
    }

    /**
     * Get user claims from the given SCIM object string and Schema string.
     *
     * @param scimUserObjectString      SCIM 2.0 Payload of a user info.
     * @param wso2IS7SCIMSchemasClient  WSO2IS7SCIMSchemasClient object to get the SCIM schemas.
     * @param accessToken               Access token to authenticate the request to WSO2 IS 7.x.
     * @param keyManagerConfiguration   KeyManagerConfiguration object containing configurations for the key manager.
     * @param tenantDomain              Tenant domain of the user.
     * @return                          A map that contains the SCIM URI and the value of the claim.
     * @throws APIManagementException   If an error occurs while decoding the SCIM object, or getting the claims.
     */
    public static Map<String, String> getUserClaims(String scimUserObjectString,
                                                    WSO2IS7SCIMSchemasClient wso2IS7SCIMSchemasClient,
                                                    String accessToken, KeyManagerConfiguration keyManagerConfiguration,
                                                    String tenantDomain) throws APIManagementException {
        JSONDecoder jsonDecoder = new JSONDecoder();
        SCIMResourceTypeSchema schema = null;

        if (keyManagerConfiguration != null &&
                keyManagerConfiguration.getParameter(WSO2ISConstants.ENABLE_SCHEMA_CACHE) instanceof Boolean &&
                Boolean.parseBoolean(
                        keyManagerConfiguration.getParameter(WSO2ISConstants.ENABLE_SCHEMA_CACHE).toString())) {
            String userSchemaCacheKey = keyManagerConfiguration.getName() + ":" + tenantDomain;

            Object cache = APIUtil.getCache(APIConstants.API_MANAGER_CACHE_MANAGER,
                    WSO2ISConstants.USER_SCHEMA_CACHE).get(userSchemaCacheKey);

            if (cache instanceof SCIMResourceTypeSchema) {
                schema = (SCIMResourceTypeSchema) cache;
            }
            if (schema == null) {
                synchronized (userSchemaCacheKey.intern()) {
                    cache = APIUtil.getCache(APIConstants.API_MANAGER_CACHE_MANAGER,
                            WSO2ISConstants.USER_SCHEMA_CACHE).get(userSchemaCacheKey);
                    if (cache instanceof SCIMResourceTypeSchema) {
                        schema = (SCIMResourceTypeSchema) cache;
                    } else {
                        schema = getUserSchema(wso2IS7SCIMSchemasClient, accessToken);
                        if (schema != null) {
                            APIUtil.getCache(APIConstants.API_MANAGER_CACHE_MANAGER,
                                    WSO2ISConstants.USER_SCHEMA_CACHE).put(userSchemaCacheKey, schema);
                        }
                    }
                }
            }
        } else {
            schema = getUserSchema(wso2IS7SCIMSchemasClient, accessToken);
        }

        Map<String, String> claims = new HashMap<>();
        try {
            AbstractSCIMObject abstractSCIMObject = jsonDecoder.decode(scimUserObjectString, schema);
            if (abstractSCIMObject instanceof User) {
                claims = getClaimsMap(abstractSCIMObject);
            }
        } catch (CharonException | BadRequestException e) {
            throw new APIManagementException("Error occurred while decoding the user attributes", e);
        }
        return claims;
    }

    /**
     * Get the user schemas.
     *
     * @param wso2IS7SCIMSchemasClient  WSO2IS7SCIMSchemasClient object to get the SCIM schemas.
     * @param accessToken               Access token to authenticate the request to WSO2 IS 7.x.
     * @return A SCIMResourceTypeSchema representing the user schema.
     * @throws APIManagementException If an error occurs while processing the SCIM schema object.
     */
    private static SCIMResourceTypeSchema getUserSchema(WSO2IS7SCIMSchemasClient wso2IS7SCIMSchemasClient,
                                                        String accessToken) throws APIManagementException {
        String customSchemaUri = WSO2ISConstants.SCIM2_CUSTOM_SCHEMA_URI;
        SCIMResourceTypeSchema schema = SCIMResourceTypeSchema.createSCIMResourceSchema(
                new ArrayList<>(SCIM_USER_SCHEMA.getSchemasList()),
                SCIM_USER_SCHEMA.getAttributesList().toArray(new AttributeSchema[0]));

        AttributeSchema customAttributes = null;
        AttributeSchema extensionAttributes = SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema();
        try {
            JsonArray scimSchemaObject = null;
            if (wso2IS7SCIMSchemasClient != null && accessToken != null) {
                scimSchemaObject = wso2IS7SCIMSchemasClient.getSchemas(accessToken);
            }

            if (scimSchemaObject != null) {
                for (JsonElement element : scimSchemaObject) {
                    JsonObject obj = element.isJsonObject() ? element.getAsJsonObject() : null;
                    String id = obj != null && obj.get(SCIMConstants.CommonSchemaConstants.ID) != null ?
                            obj.get(SCIMConstants.CommonSchemaConstants.ID).getAsString() : StringUtils.EMPTY;
                    if (SCIM2_ENTERPRISE_SCHEMA.equalsIgnoreCase(id)) {
                        if (extensionAttributes != null) {
                            addAttributesToComplexAttribute(extensionAttributes, obj, null);
                        } else {
                            extensionAttributes = mapSchemaObjectToComplexAttribute(obj, null);
                        }
                    } else if (!SCIM2_CORE_SCHEMA.equalsIgnoreCase(id)
                            && !SCIM2_USER_SCHEMA.equalsIgnoreCase(id) && !SCIM2_SYSTEM_SCHEMA_URI.equalsIgnoreCase(id)
                            && !StringUtils.EMPTY.equalsIgnoreCase(id)) {
                        customSchemaUri = id;
                        customAttributes = mapSchemaObjectToComplexAttribute(obj, null);
                    }
                }
            }

            if (extensionAttributes != null) {
                schema.getSchemasList().add(SCIM2_ENTERPRISE_SCHEMA);
                schema.getAttributesList().add(extensionAttributes);
            }

            if (customAttributes != null) {
                schema.getSchemasList().add(customSchemaUri);
                schema.getAttributesList().add(customAttributes);
            }

            return schema;
        } catch (KeyManagerClientException e) {
            throw new APIManagementException("Error occurred while getting SCIM schemas from WSO2 IS 7.x ", e);
        }
    }

    /**
     * Return claims as a map of ClaimUri (which is mapped to SCIM attribute uri),ClaimValue.
     *
     * @param scimObject SCIM object.
     * @return A map of claims.
     * @throws APIManagementException If an error occurs while getting claims.
     */
    public static Map<String, String> getClaimsMap(AbstractSCIMObject scimObject) throws APIManagementException {
        Map<String, String> claimsMap = new HashMap<>();
        try {
            Map<String, Attribute> attributeList = scimObject.getAttributeList();
            for (Map.Entry<String, Attribute> attributeEntry : attributeList.entrySet()) {
                Attribute attribute = attributeEntry.getValue();
                // if the attribute is password, skip it
                if (SCIMConstants.UserSchemaConstants.PASSWORD.equals(attribute.getName())) {
                    continue;
                }
                if (attribute instanceof SimpleAttribute) {
                    setClaimsForSimpleAttribute(attribute, claimsMap);

                } else if (attribute instanceof MultiValuedAttribute) {
                    setClaimsForMultivaluedAttribute(attribute, claimsMap);
                } else if (attribute instanceof ComplexAttribute) {
                /*
                NOTE: in carbon, we only support storing of type and value of a complex multi-valued attribute
                reading attributes list of the complex attribute.
                 */
                    ComplexAttribute complexAttribute = (ComplexAttribute) attribute;
                    Map<String, Attribute> attributes = null;
                    if (complexAttribute.getSubAttributesList() != null &&
                            MapUtils.isNotEmpty(complexAttribute.getSubAttributesList())) {
                        attributes = complexAttribute.getSubAttributesList();
                    }
                    if (attributes != null) {
                        for (Attribute entry : attributes.values()) {
                            // if the attribute a simple attribute
                            if (entry instanceof SimpleAttribute) {
                                setClaimsForSimpleAttribute(entry, claimsMap);

                            } else if (entry instanceof MultiValuedAttribute) {
                                setClaimsForMultivaluedAttribute(entry, claimsMap);

                            } else if (entry instanceof ComplexAttribute) {
                                setClaimsForComplexAttribute(entry, claimsMap);
                            }
                        }
                    }
                }
            }
        } catch (CharonException e) {
            throw new APIManagementException("Error occurred while getting claims", e);
        }
        return claimsMap;
    }

    /**
     * Set claim mapping for simple attribute.
     *
     * @param attribute Target attribute.
     * @param claimsMap A map containing claims and corresponding values to be set for the target attribute.
     */
    private static void setClaimsForSimpleAttribute(Attribute attribute, Map<String, String> claimsMap)
            throws CharonException {

        String attributeURI = attribute.getURI();
        if (((SimpleAttribute) attribute).getValue() != null) {
            String attributeValue = AttributeUtil.getStringValueOfAttribute(
                    ((SimpleAttribute) attribute).getValue(), attribute.getType());
            // set attribute URI as the claim URI
            claimsMap.put(attributeURI, attributeValue);
        }
    }

    /**
     * Set claim mapping for multivalued attribute.
     *
     * @param attribute Target attribute.
     * @param claimsMap A map containing claims and corresponding values to be set for the target attribute.
     */
    private static void setClaimsForMultivaluedAttribute(Attribute attribute, Map<String, String> claimsMap)
            throws CharonException {

        MultiValuedAttribute multiValAttribute = (MultiValuedAttribute) attribute;
        // Get the URI of root attribute.
        String attributeURI = multiValAttribute.getURI();
        // Check if values are set as primitive values.
        List<Object> attributeValues = multiValAttribute.getAttributePrimitiveValues();
        if (CollectionUtils.isNotEmpty(attributeValues)) {
            String values = attributeValues.stream()
                    .map(obj -> "\"" + String.valueOf(obj) + "\"")
                    .collect(Collectors.joining(WSO2ISConstants.MULTIVALUED_ATTRIBUTE_SEPARATOR, "[", "]"));
            claimsMap.put(attributeURI, values);
        }

        // check if values are set as complex values
        // NOTE: in carbon, we only support storing of type and
        // value of a multi-valued attribute
        List<Attribute> complexAttributeList = multiValAttribute.getAttributeValues();
        List<String> multiAttributes = new ArrayList<>();
        for (Attribute complexAttrib : complexAttributeList) {
            Map<String, Attribute> subAttributes =
                    ((ComplexAttribute) complexAttrib).getSubAttributesList();
            SimpleAttribute typeAttribute =
                    (SimpleAttribute) subAttributes.get(SCIMConstants.CommonSchemaConstants.TYPE);
            String valueAttriubuteURI;
            // construct attribute URI
            String typeValue = null;
            if (typeAttribute != null) {
                typeValue = (String) typeAttribute.getValue();
                valueAttriubuteURI = attributeURI + "." + typeValue;
            } else {
                valueAttriubuteURI = attributeURI;
            }
            SimpleAttribute valueAttribute = null;
            if (attribute.getName().equals(SCIMConstants.UserSchemaConstants.ADDRESSES)) {
                valueAttribute =
                        (SimpleAttribute) subAttributes.get(SCIMConstants.UserSchemaConstants.FORMATTED_ADDRESS);
            } else if (attribute.getName().equals(SCIMConstants.UserSchemaConstants.GROUPS)
                    || attribute.getName().equals(SCIMConstants.UserSchemaConstants.ROLES)) {
                valueAttribute =
                        (SimpleAttribute) subAttributes.get(SCIMConstants.CommonSchemaConstants.DISPLAY);
            } else {
                valueAttribute = (SimpleAttribute) subAttributes.get(SCIMConstants.CommonSchemaConstants.VALUE);
            }
            if (valueAttribute != null && valueAttribute.getValue() != null) {
                String attributeString = AttributeUtil.getStringValueOfAttribute(
                        valueAttribute.getValue(), valueAttribute.getType());
                if (typeAttribute != null) {
                    claimsMap.put(valueAttriubuteURI, attributeString);
                } else {
                    multiAttributes.add(attributeString);
                }
            }

            boolean isComplexMultivaluedSupportEnabled = Boolean.parseBoolean(IdentityUtil.getProperty
                    (SCIM_COMPLEX_MULTIVALUED_ATTRIBUTE_SUPPORT_ENABLED));
            if (isComplexMultivaluedSupportEnabled) {
                Map<String, Attribute> otherAttributes = new HashMap<>(subAttributes);
                otherAttributes.remove(SCIMConstants.CommonSchemaConstants.TYPE);
                otherAttributes.remove(SCIMConstants.CommonSchemaConstants.VALUE);
                for (Map.Entry<String, Attribute> entry : otherAttributes.entrySet()) {
                    if (entry.getValue() instanceof SimpleAttribute) {
                        setClaimsForSimpleSubAttributeOfMultivaluedComplexAttribute(attributeURI, entry.getValue(),
                                claimsMap, typeValue);
                    }
                }
            }
        }
        if (CollectionUtils.isNotEmpty(multiAttributes)) {
            String multiAttributeValues = multiAttributes.stream()
                    .map(s -> "\"" + s + "\"")
                    .collect(Collectors.joining(WSO2ISConstants.MULTIVALUED_ATTRIBUTE_SEPARATOR, "[", "]"));
            // set attribute URI as the claim URI
            claimsMap.put(attributeURI, multiAttributeValues);
        }
    }

    private static void setClaimsForSimpleSubAttributeOfMultivaluedComplexAttribute(String parentURI, Attribute
            attribute, Map<String, String> claimsMap, String type) throws CharonException {

        String attributeKey = attribute.getURI().replace(parentURI + ".", "");
        String attributeURI = parentURI + ADVANCED_ATTRIBUTE_IDENTIFIER + type + "." + attributeKey;
        if (((SimpleAttribute) attribute).getValue() != null) {
            String attributeValue = AttributeUtil.getStringValueOfAttribute(((SimpleAttribute) attribute).getValue(),
                    attribute.getType());
            // set attribute URI as the claim URI
            claimsMap.put(attributeURI, attributeValue);
        }
    }

    /**
     * Set claim mapping for complex attribute.
     *
     * @param entry     Target attribute.
     * @param claimsMap A map containing claims and corresponding values to be set for the target attribute.
     */
    private static void setClaimsForComplexAttribute(Attribute entry, Map<String, String> claimsMap)
            throws CharonException {

        // Reading attributes list of the complex attribute.
        ComplexAttribute entryOfComplexAttribute = (ComplexAttribute) entry;
        Map<String, Attribute> entryAttributes;
        if (entryOfComplexAttribute.getSubAttributesList() != null &&
                MapUtils.isNotEmpty(entryOfComplexAttribute.getSubAttributesList())) {
            entryAttributes = entryOfComplexAttribute.getSubAttributesList();
            for (Attribute subEntry : entryAttributes.values()) {
                // attribute can only be simple attribute and that also in the extension schema only
                if (subEntry.getMultiValued()) {
                    setClaimsForMultivaluedAttribute(subEntry, claimsMap);
                } else {
                    setClaimsForSimpleAttribute(subEntry, claimsMap);
                }
            }
        }
    }

    /**
     * Map the given SCIM schema object to a complex attribute schema.
     *
     * @param scimSchemaObject The SCIM schema object to be mapped.
     * @param rootId The root ID of the schema, used to create unique IDs for sub-attributes.
     * @return A complex attribute schema.
     * @throws APIManagementException If an error occurs while mapping the schema object.
     */
    private static AttributeSchema mapSchemaObjectToComplexAttribute(JsonObject scimSchemaObject, String rootId)
            throws APIManagementException {
        String uri = rootId != null ? rootId
                : scimSchemaObject.get(SCIMConstants.CommonSchemaConstants.ID).getAsString();
        AttributeSchema complexAttr = SCIMAttributeSchema.createSCIMAttributeSchema(
                uri,
                uri,
                SCIMDefinitions.DataType.COMPLEX,
                scimSchemaObject.get(WSO2ISConstants.MULTI_VALUED) != null &&
                        Boolean.TRUE.equals(scimSchemaObject.get(WSO2ISConstants.MULTI_VALUED).getAsBoolean()),
                scimSchemaObject.get(SCIMConstants.CustomUserSchemaConstants.DESCRIPTION) != null
                        ? scimSchemaObject.get(SCIMConstants.CustomUserSchemaConstants.DESCRIPTION)
                        .getAsString() : StringUtils.EMPTY,
                scimSchemaObject.get(WSO2ISConstants.REQUIRED) != null &&
                        Boolean.TRUE.equals(scimSchemaObject.get(WSO2ISConstants.REQUIRED).getAsBoolean()),
                scimSchemaObject.get(WSO2ISConstants.CASE_EXACT) != null &&
                        Boolean.TRUE.equals(scimSchemaObject.get(WSO2ISConstants.CASE_EXACT).getAsBoolean()),
                scimSchemaObject.get(WSO2ISConstants.MUTABILITY) != null ?
                        SCIMDefinitions.Mutability.valueOf(
                                StringUtils.upperCase(scimSchemaObject.get(WSO2ISConstants.MUTABILITY).getAsString())) :
                        SCIMDefinitions.Mutability.READ_WRITE,
                scimSchemaObject.get(WSO2ISConstants.RETURNED) != null ?
                        SCIMDefinitions.Returned.valueOf(
                                StringUtils.upperCase(scimSchemaObject.get(WSO2ISConstants.RETURNED).getAsString())) :
                        SCIMDefinitions.Returned.DEFAULT,
                scimSchemaObject.get(WSO2ISConstants.UNIQUENESS) != null ?
                        SCIMDefinitions.Uniqueness.valueOf(
                                StringUtils.upperCase(scimSchemaObject.get(WSO2ISConstants.UNIQUENESS).getAsString())) :
                        SCIMDefinitions.Uniqueness.NONE,
                setCanonicalValues(scimSchemaObject.get(WSO2ISConstants.CANONICAL_VALUES)),
                setReferenceTypes(scimSchemaObject.get(WSO2ISConstants.REFERENCE_TYPES)),
                new ArrayList<>()
        );

        addAttributesToComplexAttribute(complexAttr, scimSchemaObject, uri);
        return complexAttr;
    }

    /**
     * Add attributes to a given complex attribute schema.
     *
     * @param complexAttribute The complex attribute schema to which attributes will be added.
     * @param scimSchemaObject The SCIM schema object containing the attributes to be added.
     * @param rootId The root ID of the schema, used to create unique IDs for sub-attributes.
     * @throws APIManagementException If an error occurs while adding attributes.
     */
    private static void addAttributesToComplexAttribute(AttributeSchema complexAttribute,
                                                        JsonObject scimSchemaObject, String rootId)
            throws APIManagementException {

        if (complexAttribute == null) {
            return;
        }

        JsonElement attributes = scimSchemaObject.get(SCIMConstants.CommonSchemaConstants.ATTRIBUTES);

        if (attributes == null || !attributes.isJsonArray()) {
            attributes = scimSchemaObject.get("subAttributes");
            if (attributes == null || !attributes.isJsonArray()) {
                // If no attributes are defined, return the complex attribute with no sub-attributes.
                return;
            }
        }

        ArrayList<String> existingAttributes = complexAttribute.getSubAttributeSchemas().stream()
                .map(AttributeSchema::getName)
                .collect(Collectors.toCollection(ArrayList::new));

        for (JsonElement attr : attributes.getAsJsonArray()) {
            if (!attr.isJsonObject()) {
                continue;
            }
            JsonObject attribute = attr.getAsJsonObject();

            // Check for the required fields in the attribute object.
            if (attribute.get(SCIMConstants.UserSchemaConstants.NAME) == null) {
                throw new APIManagementException(
                        "Invalid SCIM schema object: 'name' field is required for each attribute."
                );
            }

            if (rootId == null && scimSchemaObject.get(SCIMConstants.CommonSchemaConstants.ID) == null) {
                throw new APIManagementException(
                        "Invalid SCIM schema object: 'id' " +
                                "field is required for the root attribute if 'rootId' is not provided."
                );
            }

            String name = attribute.get(SCIMConstants.UserSchemaConstants.NAME).getAsString();
            String type = attribute.get(SCIMConstants.CommonSchemaConstants.TYPE) != null ?
                    StringUtils.upperCase(attribute.get(SCIMConstants.CommonSchemaConstants.TYPE).getAsString())
                    : SCIMDefinitions.DataType.STRING.toString();
            String uri = scimSchemaObject.get(SCIMConstants.CommonSchemaConstants.ID) != null ?
                    scimSchemaObject.get(SCIMConstants.CommonSchemaConstants.ID).getAsString() + ":" + name
                    : rootId + "." + name;

            if (existingAttributes.contains(name)) {
                continue;
            }

            AttributeSchema subAttr;
            if (StringUtils.upperCase(type).equals(SCIMDefinitions.DataType.COMPLEX.toString())) {
                // If the type is complex, recursively map to a complex attribute.
                subAttr = mapSchemaObjectToComplexAttribute(attribute, uri);
            } else {
                subAttr = SCIMAttributeSchema.createSCIMAttributeSchema(
                        uri,
                        name,
                        SCIMDefinitions.DataType.valueOf(type),
                        attribute.get(WSO2ISConstants.MULTI_VALUED) != null &&
                                Boolean.TRUE.equals(attribute.get(WSO2ISConstants.MULTI_VALUED).getAsBoolean()),
                        attribute.get(SCIMConstants.CustomUserSchemaConstants.DESCRIPTION) != null ?
                                attribute.get(SCIMConstants.CustomUserSchemaConstants.DESCRIPTION)
                                        .getAsString() : StringUtils.EMPTY,
                        attribute.get(WSO2ISConstants.REQUIRED) != null &&
                                Boolean.TRUE.equals(attribute.get(WSO2ISConstants.REQUIRED).getAsBoolean()),
                        attribute.get(WSO2ISConstants.CASE_EXACT) != null &&
                                Boolean.TRUE.equals(attribute.get(WSO2ISConstants.CASE_EXACT).getAsBoolean()),
                        attribute.get(WSO2ISConstants.MUTABILITY) != null ?
                                SCIMDefinitions.Mutability.valueOf(StringUtils.upperCase(
                                        attribute.get(WSO2ISConstants.MUTABILITY).getAsString())) :
                                SCIMDefinitions.Mutability.READ_WRITE,
                        attribute.get(WSO2ISConstants.RETURNED) != null ?
                                SCIMDefinitions.Returned.valueOf(
                                        StringUtils.upperCase(attribute.get(WSO2ISConstants.RETURNED).getAsString())) :
                                SCIMDefinitions.Returned.DEFAULT,
                        attribute.get(WSO2ISConstants.UNIQUENESS) != null ?
                                SCIMDefinitions.Uniqueness.valueOf(StringUtils.upperCase(
                                        attribute.get(WSO2ISConstants.UNIQUENESS).getAsString())) :
                                SCIMDefinitions.Uniqueness.NONE,
                        setCanonicalValues(attribute.get(WSO2ISConstants.CANONICAL_VALUES)),
                        setReferenceTypes(attribute.get(WSO2ISConstants.REFERENCE_TYPES)),
                        new ArrayList<>()
                );
            }
            complexAttribute.getSubAttributeSchemas().add(subAttr);
        }
    }

    /**
     * Set canonical values for the given input.
     *
     * @param input The input JSON element containing canonical values.
     * @return A list of canonical values as strings.
     * @throws APIManagementException If the input is not a valid JSON array or contains invalid values.
     */
    private static ArrayList<String> setCanonicalValues(JsonElement input) throws APIManagementException {
        ArrayList<String> canonicalValues = new ArrayList<>();
        JsonArray canonicalValuesList = null;

        if (input != null && input.isJsonArray()) {
            canonicalValuesList = input.getAsJsonArray();
        }

        if (canonicalValuesList == null || canonicalValuesList.size() == 0) {
            return canonicalValues;
        }

        for (JsonElement element : canonicalValuesList) {
            if (element.isJsonPrimitive() && element.getAsJsonPrimitive().isString()) {
                canonicalValues.add(element.getAsString());
            } else {
                throw new APIManagementException("Invalid canonical value: " + element.toString() +
                        ". Expected a string value.");
            }
        }

        return canonicalValues;
    }

    /**
     * Set reference types for the given input.
     *
     * @param input The input JSON element containing reference types.
     * @return A list of reference types as SCIMDefinitions.ReferenceType.
     * @throws APIManagementException If the input is not a valid JSON array or contains invalid values.
     */
    private static ArrayList<SCIMDefinitions.ReferenceType> setReferenceTypes(JsonElement input)
            throws APIManagementException {
        ArrayList<SCIMDefinitions.ReferenceType> referenceTypes = new ArrayList<>();
        if (input == null || !input.isJsonArray()) {
            return referenceTypes;
        }
        JsonArray referenceTypesList = input.getAsJsonArray();

        for (JsonElement element : referenceTypesList) {
            if (!element.isJsonPrimitive() || !element.getAsJsonPrimitive().isString()) {
                throw new APIManagementException(
                        "Invalid reference type: " + element.toString() + ". Expected a string value."
                );
            }
            String referenceValue = element.getAsString();
            if (referenceValue.equalsIgnoreCase("external")) {
                referenceTypes.add(SCIMDefinitions.ReferenceType.EXTERNAL);
            } else if (referenceValue.equalsIgnoreCase("user")) {
                referenceTypes.add(SCIMDefinitions.ReferenceType.USER);
            } else if (referenceValue.equalsIgnoreCase("group")) {
                referenceTypes.add(SCIMDefinitions.ReferenceType.GROUP);
            } else if (referenceValue.equalsIgnoreCase("uri")) {
                referenceTypes.add(SCIMDefinitions.ReferenceType.URI);
            }

        }

        return referenceTypes;
    }

}
