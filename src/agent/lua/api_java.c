#include <agent/lua_java.h>
#include <agent/lua_engine.h>
#include <agent/globals.h>
#include <agent/agent.h>

#include <dlfcn.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

#define MAX_PARAMS 16
#define MAX_CLASS_NAME 256

typedef struct {
    jclass clazz;
    char class_name[MAX_CLASS_NAME];
} JavaClassWrapper;

typedef struct {
    char param_types[MAX_PARAMS];           // 'I', 'Z', 'L', '[' etc.
    char param_class_names[MAX_PARAMS][MAX_CLASS_NAME];
    int param_count;
    char return_type;
    char return_class_name[MAX_CLASS_NAME];
} ParsedSignature;

static jobject g_class_loader = NULL;
static jmethodID g_load_class_method = NULL;

static bool setup_class_loader(JNIEnv* env) {
    if (g_class_loader != NULL) {
        return true;
    }

    jclass thread_class = (*env)->FindClass(env, "java/lang/Thread");
    if (!thread_class) {
        LOGE("Failed to find Thread class");
        return false;
    }

    jmethodID current_thread = (*env)->GetStaticMethodID(
            env, thread_class, "currentThread", "()Ljava/lang/Thread;");
    if (!current_thread) {
        LOGE("Failed to find currentThread method");
        return false;
    }

    jobject thread = (*env)->CallStaticObjectMethod(env, thread_class, current_thread);
    if (!thread) {
        LOGE("Failed to get current thread");
        return false;
    }

    jmethodID get_class_loader = (*env)->GetMethodID(
            env, thread_class, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
    if (!get_class_loader) {
        LOGE("Failed to find getContextClassLoader method");
        return false;
    }

    jobject class_loader = (*env)->CallObjectMethod(env, thread, get_class_loader);
    if (!class_loader) {
        LOGE("Failed to get ClassLoader");
        return false;
    }

    g_class_loader = (*env)->NewGlobalRef(env, class_loader);

    jclass class_loader_class = (*env)->FindClass(env, "java/lang/ClassLoader");
    g_load_class_method = (*env)->GetMethodID(
            env, class_loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");

    LOGI("ClassLoader setup complete");
    return true;
}

static jclass find_class(JNIEnv* env, const char* class_name) {
    jclass clazz = (*env)->FindClass(env, class_name);
    if (clazz) {
        (*env)->ExceptionClear(env);
        LOGI("Found class via FindClass: %s", class_name);
        return clazz;
    }
    (*env)->ExceptionClear(env);

    if (!setup_class_loader(env)) {
        LOGE("ClassLoader setup failed");
        return NULL;
    }

    char java_class_name[256];
    strncpy(java_class_name, class_name, sizeof(java_class_name) - 1);
    java_class_name[sizeof(java_class_name) - 1] = '\0';

    for (size_t i = 0; java_class_name[i] != '\0'; i++) {
        if (java_class_name[i] == '/') {
            java_class_name[i] = '.';
        }
    }

    jstring class_name_str = (*env)->NewStringUTF(env, java_class_name);
    clazz = (jclass)(*env)->CallObjectMethod(
            env, g_class_loader, g_load_class_method, class_name_str);

    (*env)->DeleteLocalRef(env, class_name_str);

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        LOGE("Failed to load class: %s", class_name);
        return NULL;
    }

    LOGI("Found class via ClassLoader: %s", class_name);
    return clazz;
}

static ParsedSignature parse_signature(const char* sig) {
    ParsedSignature result;
    memset(&result, 0, sizeof(result));

    const char* p = sig;

    if (*p != '(') {
        LOGE("Invalid signature: %s", sig);
        return result;
    }
    p++;

    while (*p && *p != ')' && result.param_count < MAX_PARAMS) {
        if (*p == 'L') {
            result.param_types[result.param_count] = 'L';
            p++;

            size_t class_idx = 0;
            while (*p && *p != ';' && class_idx < MAX_CLASS_NAME - 1) {
                result.param_class_names[result.param_count][class_idx++] = *p++;
            }
            result.param_class_names[result.param_count][class_idx] = '\0';

            if (*p == ';') p++;
            result.param_count++;
        } else if (*p == '[') {
            result.param_types[result.param_count] = '[';
            result.param_class_names[result.param_count][0] = '\0';
            result.param_count++;
            p++;
            if (*p == 'L') {
                while (*p && *p != ';') p++;
                if (*p == ';') p++;
            } else if (*p) {
                p++;
            }
        } else {
            // Primitive type: I, Z, B, C, S, J, F, D, V
            result.param_types[result.param_count] = *p;
            result.param_class_names[result.param_count][0] = '\0';
            result.param_count++;
            p++;
        }
    }

    if (*p == ')') p++;

    // Return type
    if (*p == 'L') {
        result.return_type = 'L';
        p++;
        size_t class_idx = 0;
        while (*p && *p != ';' && class_idx < MAX_CLASS_NAME - 1) {
            result.return_class_name[class_idx++] = *p++;
        }
        result.return_class_name[class_idx] = '\0';
    } else if (*p == '[') {
        result.return_type = '[';
        result.return_class_name[0] = '\0';
    } else if (*p) {
        result.return_type = *p;
        result.return_class_name[0] = '\0';
    }

    LOGI("Parsed signature: %d params, return type: %c", result.param_count, result.return_type);

    return result;
}

//=============================================================================
// Java.use() 
//=============================================================================
static JavaClassWrapper* java_use(JNIEnv* env, const char* class_name) {
    jclass clazz = find_class(env, class_name);
    if (!clazz) {
        return NULL;
    }

    // Global reference al (wrapper'ın ömrü boyunca yaşasın)
    jclass global_clazz = (jclass)(*env)->NewGlobalRef(env, clazz);
    (*env)->DeleteLocalRef(env, clazz);

    // Wrapper oluştur
    JavaClassWrapper* wrapper = (JavaClassWrapper*)malloc(sizeof(JavaClassWrapper));
    if (!wrapper) {
        (*env)->DeleteGlobalRef(env, global_clazz);
        return NULL;
    }

    wrapper->clazz = global_clazz;
    strncpy(wrapper->class_name, class_name, MAX_CLASS_NAME - 1);
    wrapper->class_name[MAX_CLASS_NAME - 1] = '\0';

    return wrapper;
}

//=============================================================================
// $new() 
//=============================================================================
static jobject java_new(JNIEnv* env, JavaClassWrapper* wrapper,
                        const char* constructor_sig, jvalue* args) {

    jmethodID constructor = (*env)->GetMethodID(env, wrapper->clazz, "<init>", constructor_sig);
    if (!constructor) {
        LOGE("Constructor not found: %s", constructor_sig);
        (*env)->ExceptionClear(env);
        return NULL;
    }

    jobject instance = (*env)->NewObjectA(env, wrapper->clazz, constructor, args);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        LOGE("Failed to create instance");
        return NULL;
    }

    LOGI("Created new instance of %s", wrapper->class_name);
    return instance;
}

//=============================================================================
// Static method CALL
//=============================================================================
static jvalue call_static_method(JNIEnv* env, JavaClassWrapper* wrapper,
                                 const char* method_name, const char* signature,
                                 jvalue* args) {
    jvalue result;
    memset(&result, 0, sizeof(result));

    jmethodID method = (*env)->GetStaticMethodID(env, wrapper->clazz, method_name, signature);
    if (!method) {
        LOGE("Static method not found: %s%s", method_name, signature);
        (*env)->ExceptionClear(env);
        return result;
    }

    ParsedSignature parsed = parse_signature(signature);

    switch (parsed.return_type) {
        case 'V':
            (*env)->CallStaticVoidMethodA(env, wrapper->clazz, method, args);
            break;
        case 'Z':
            result.z = (*env)->CallStaticBooleanMethodA(env, wrapper->clazz, method, args);
            break;
        case 'I':
            result.i = (*env)->CallStaticIntMethodA(env, wrapper->clazz, method, args);
            break;
        case 'J':
            result.j = (*env)->CallStaticLongMethodA(env, wrapper->clazz, method, args);
            break;
        case 'F':
            result.f = (*env)->CallStaticFloatMethodA(env, wrapper->clazz, method, args);
            break;
        case 'D':
            result.d = (*env)->CallStaticDoubleMethodA(env, wrapper->clazz, method, args);
            break;
        case 'L':
        case '[':
            result.l = (*env)->CallStaticObjectMethodA(env, wrapper->clazz, method, args);
            break;
        default:
            LOGE("Unknown return type: %c", parsed.return_type);
    }

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    return result;
}

static void lua_to_jvalue(JNIEnv* env, lua_State* L , ParsedSignature* sig, jvalue* args, int start_pos){
    for (int i = 0; i < sig->param_count; i++) {
        int stack_pos = start_pos + i;


        switch(sig->param_types[i]){
        case 'I':
            args[i].i = lua_tointeger(L, stack_pos);
            break;
        case 'Z':
            args[i].z = lua_toboolean(L, stack_pos);
            break;
        case 'L':
            if (lua_isstring(L,stack_pos)){
                args[i].l = (*env)->NewStringUTF(env, lua_tostring(L,stack_pos));
            }else{
                jobject* obj_ud = (jobject*)lua_touserdata(L, stack_pos);
                args[i].l = *obj_ud;
            }
            break;
        case 'F':
            args[i].f = lua_tonumber(L, stack_pos);
            break;
        case 'D':
            args[i].d = lua_tonumber(L, stack_pos);
            break;
        case 'B':
            args[i].b = lua_tointeger(L, stack_pos);
            break;
        case 'S':
            args[i].s = lua_tointeger(L, stack_pos);
            break;
        case 'C':
            args[i].c = lua_tointeger(L, stack_pos);
            break;
        case 'J':
            args[i].j = lua_tointeger(L, stack_pos);
            break;
        }
    }
}

//=============================================================================
// Instance method CALL
//=============================================================================
static jvalue call_instance_method(JNIEnv* env, jobject instance,
                                   const char* method_name, const char* signature,
                                   jvalue* args) {
    jvalue result;
    memset(&result, 0, sizeof(result));

    jclass clazz = (*env)->GetObjectClass(env, instance);
    jmethodID method = (*env)->GetMethodID(env, clazz, method_name, signature);
    if (!method) {
        LOGE("Instance method not found: %s%s", method_name, signature);
        (*env)->ExceptionClear(env);
        return result;
    }

    ParsedSignature parsed = parse_signature(signature);

    switch (parsed.return_type) {
        case 'V':
            (*env)->CallVoidMethodA(env, instance, method, args);
            break;
        case 'Z':
            result.z = (*env)->CallBooleanMethodA(env, instance, method, args);
            break;
        case 'I':
            result.i = (*env)->CallIntMethodA(env, instance, method, args);
            break;
        case 'J':
            result.j = (*env)->CallLongMethodA(env, instance, method, args);
            break;
        case 'F':
            result.f = (*env)->CallFloatMethodA(env, instance, method, args);
            break;
        case 'D':
            result.d = (*env)->CallDoubleMethodA(env, instance, method, args);
            break;
        case 'L':
        case '[':
            result.l = (*env)->CallObjectMethodA(env, instance, method, args);
            break;
        default:
            LOGE("Unknown return type: %c", parsed.return_type);
    }

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    return result;
}

//=============================================================================
// Lua Bindings
//=============================================================================

// Userdata type name
#define JAVA_WRAPPER_MT "JavaClassWrapper"
#define JAVA_INSTANCE_MT "JavaInstance"

// Java.use("com.example.Class") -> JavaClassWrapper userdata
static int lua_java_use(lua_State* L) {
    const char* class_name = luaL_checkstring(L, 1);

    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to get JNIEnv");
        return 2;
    }

    JavaClassWrapper* wrapper = java_use(env, class_name);
    if (!wrapper) {
        lua_pushnil(L);
        lua_pushstring(L, "Class not found");
        return 2;
    }

    JavaClassWrapper** ud = (JavaClassWrapper**)lua_newuserdata(L, sizeof(JavaClassWrapper*));
    *ud = wrapper;

    // Metatable ekle
    luaL_getmetatable(L, JAVA_WRAPPER_MT);
    lua_setmetatable(L, -2);

    return 1;
}

static int lua_java_new(lua_State* L) {
    JavaClassWrapper** ud = (JavaClassWrapper**)luaL_checkudata(L, 1, JAVA_WRAPPER_MT);
    JavaClassWrapper* wrapper = *ud;
    const char* sig = luaL_optstring(L, 2, "()V");

    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to get JNIEnv");
        return 2;
    }
    

    jvalue args[MAX_PARAMS];
    memset(args, 0, sizeof(args));

    ParsedSignature parsed = parse_signature(sig);
    lua_to_jvalue(env, L, &parsed, args, 3);
    
    jobject instance = java_new(env, wrapper, sig, args);
    if (!instance) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to create instance");
        return 2;
    }

    jobject global_instance = (*env)->NewGlobalRef(env, instance);
    (*env)->DeleteLocalRef(env, instance);

    jobject* inst_ud = (jobject*)lua_newuserdata(L, sizeof(jobject));
    *inst_ud = global_instance;

    luaL_getmetatable(L, JAVA_INSTANCE_MT);
    lua_setmetatable(L, -2);

    return 1;
}

static int lua_java_call_static(lua_State* L) {
    JavaClassWrapper** ud = (JavaClassWrapper**)luaL_checkudata(L, 1, JAVA_WRAPPER_MT);
    JavaClassWrapper* wrapper = *ud;
    const char* method_name = luaL_checkstring(L, 2);
    const char* sig = luaL_checkstring(L, 3);

    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        return 1;
    }

    jvalue args[MAX_PARAMS];
    memset(args, 0, sizeof(args));
    
    ParsedSignature parsed = parse_signature(sig);
    lua_to_jvalue(env,L,&parsed,args,4);
    

    jvalue result = call_static_method(env, wrapper, method_name, sig, args);



    switch (parsed.return_type) {
        case 'V':
            return 0;
        case 'Z':
            lua_pushboolean(L, result.z);
            return 1;
        case 'I':
            lua_pushinteger(L, result.i);
            return 1;
        case 'J':
            lua_pushinteger(L, (lua_Integer)result.j);
            return 1;
        case 'F':
            lua_pushnumber(L, result.f);
            return 1;
        case 'D':
            lua_pushnumber(L, result.d);
            return 1;
        case 'L':
        case '[':
            if (result.l) {
                jclass string_class = (*env)->FindClass(env, "java/lang/String");
                if ((*env)->IsInstanceOf(env, result.l, string_class)) {
                    const char* str = (*env)->GetStringUTFChars(env, (jstring)result.l, NULL);
                    lua_pushstring(L, str);
                    (*env)->ReleaseStringUTFChars(env, (jstring)result.l, str);
                } else {
                    jobject global = (*env)->NewGlobalRef(env, result.l);
                    jobject* obj_ud = (jobject*)lua_newuserdata(L, sizeof(jobject));
                    *obj_ud = global;
                    luaL_getmetatable(L, JAVA_INSTANCE_MT);
                    lua_setmetatable(L, -2);
                }
                (*env)->DeleteLocalRef(env, result.l);
            } else {
                lua_pushnil(L);
            }
            return 1;
        default:
            lua_pushnil(L);
            return 1;
    }
}

static int lua_java_call_instance(lua_State* L) {
    jobject* ud = (jobject*)luaL_checkudata(L, 1, JAVA_INSTANCE_MT);
    jobject instance = *ud;
    const char* method_name = luaL_checkstring(L, 2);
    const char* sig = luaL_checkstring(L, 3);

    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        return 1;
    }

    jvalue args[MAX_PARAMS];
    memset(args, 0, sizeof(args));

    ParsedSignature parsed = parse_signature(sig);
    lua_to_jvalue(env,L,&parsed,args,4);
    
    jvalue result = call_instance_method(env, instance, method_name, sig, args);

    switch (parsed.return_type) {
        case 'V':
            return 0;
        case 'Z':
            lua_pushboolean(L, result.z);
            return 1;
        case 'I':
            lua_pushinteger(L, result.i);
            return 1;
        case 'J':
            lua_pushinteger(L, (lua_Integer)result.j);
            return 1;
        case 'F':
            lua_pushnumber(L, result.f);
            return 1;
        case 'D':
            lua_pushnumber(L, result.d);
            return 1;
        case 'L':
        case '[':
            if (result.l) {
                jclass string_class = (*env)->FindClass(env, "java/lang/String");
                if ((*env)->IsInstanceOf(env, result.l, string_class)) {
                    const char* str = (*env)->GetStringUTFChars(env, (jstring)result.l, NULL);
                    lua_pushstring(L, str);
                    (*env)->ReleaseStringUTFChars(env, (jstring)result.l, str);
                } else {
                    jobject global = (*env)->NewGlobalRef(env, result.l);
                    jobject* obj_ud = (jobject*)lua_newuserdata(L, sizeof(jobject));
                    *obj_ud = global;
                    luaL_getmetatable(L, JAVA_INSTANCE_MT);
                    lua_setmetatable(L, -2);
                }
                (*env)->DeleteLocalRef(env, result.l);
            } else {
                lua_pushnil(L);
            }
            return 1;
        default:
            lua_pushnil(L);
            return 1;
    }
}

static int lua_java_wrapper_gc(lua_State* L) {
    JavaClassWrapper** ud = (JavaClassWrapper**)luaL_checkudata(L, 1, JAVA_WRAPPER_MT);
    JavaClassWrapper* wrapper = *ud;

    if (wrapper) {
        JNIEnv* env = get_jni_env();
        if (env && wrapper->clazz) {
            (*env)->DeleteGlobalRef(env, wrapper->clazz);
        }
        free(wrapper);
    }

    return 0;
}

static int lua_java_instance_gc(lua_State* L) {
    jobject* ud = (jobject*)luaL_checkudata(L, 1, JAVA_INSTANCE_MT);
    jobject instance = *ud;

    if (instance) {
        JNIEnv* env = get_jni_env();
        if (env) {
            (*env)->DeleteGlobalRef(env, instance);
        }
    }

    return 0;
}

static const luaL_Reg java_wrapper_methods[] = {
    {"new", lua_java_new},
    {"call", lua_java_call_static},
    {"__gc", lua_java_wrapper_gc},
    {NULL, NULL}
};

static const luaL_Reg java_instance_methods[] = {
    {"call", lua_java_call_instance},
    {"__gc", lua_java_instance_gc},
    {NULL, NULL}
};

void lua_register_java(lua_State* L) {
    luaL_newmetatable(L, JAVA_WRAPPER_MT);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, java_wrapper_methods, 0);
    lua_pop(L, 1);

    luaL_newmetatable(L, JAVA_INSTANCE_MT);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, java_instance_methods, 0);
    lua_pop(L, 1);

    lua_newtable(L);

    lua_pushcfunction(L, lua_java_use);
    lua_setfield(L, -2, "use");

    lua_setglobal(L, "Java");

    LOGI("Java API registered");
}
