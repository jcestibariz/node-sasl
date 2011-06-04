#include <v8.h>
#include <gsasl.h>
#include <map>
#include <string>

using namespace v8;
using namespace std;

static Gsasl* ctx = NULL;
static Persistent<Object> module;
static Persistent<Function> Session;
static Persistent<Object> listeners;
static map<string, Gsasl_property> properties;
static const char* propertyNames[] = {
	NULL,
	"authId",
	"authzId",
	"password",
	"anonymousToken",
	"service",
	"hostname",
	"displayName",
	"passcode",
	"suggestedPin",
	"pin",
	"realm",
	"md5HashedPassword",
	"qops",
	"qop",
	"scramIter",
	"scramSalt",
	"scramSaltedPassword",
	"cbTlsUnique"
};
static const char* validationNames[] = {
	"validateSimple",
	"validateExternal",
	"validateAnonymous",
	"validateGSSAPI",
	"validateSecurID"
};

inline Gsasl_session* GetSession(Handle<Object> self) {
	return static_cast<Gsasl_session*>(Handle<External>::Cast(self->GetInternalField(0))->Value());
}

static void ModuleReferenceCallback(Persistent<Value> object, void* parameter) {
	if (ctx) {
		gsasl_done(ctx);
		ctx = NULL;
	}
	Session.Dispose();
	listeners.Dispose();
	object.Dispose();
}

static void SessionReferenceCallback(Persistent<Value> object, void* parameter) {
	Gsasl_session* session = GetSession(Handle<Object>::Cast(object));
	if (session) {
		gsasl_finish(session);
	}
	object.Dispose();
}

static Handle<Object> GetSessionObject(Gsasl_session* session) {
	Object* ptr = static_cast<Object*>(gsasl_session_hook_get(session));
	if (ptr) {
		return Handle<Object>(ptr);
	}

	Persistent<Object> obj = Persistent<Object>::New(Session->NewInstance());
	obj.MakeWeak(NULL, SessionReferenceCallback);
	obj->SetInternalField(0, External::New(session));
	gsasl_session_hook_set(session, *obj);
	return obj;
}

static Handle<Value> Step(const Arguments& args) {
	HandleScope scope;

	if (args.Length() < 2) {
		return ThrowException(Exception::Error(String::New("Expecting two arguments")));
	}
	
	if (!args[0]->IsString()) {
		return ThrowException(Exception::TypeError(String::New("Argument 0 must be a string")));
	}
	
	if (!args[1]->IsFunction()) {
		return ThrowException(Exception::TypeError(String::New("Argument 1 must be a function")));
	}
	
	Handle<Value> argv[] = { Null(), Null(), False() };
	Gsasl_session* session = GetSession(args.This());
	char* p;
	int rc = gsasl_step64(session, *String::AsciiValue(args[0]), &p);
	if (rc == GSASL_OK || rc == GSASL_NEEDS_MORE) {
		argv[1] = String::New(p);
		argv[2] = rc == GSASL_NEEDS_MORE ? True() : False();
		gsasl_free(p);
	}
	else {
		argv[0] = Exception::Error(String::New(gsasl_strerror(rc)));
	}

	Handle<Function>::Cast(args[1])->Call(args.Holder(), 3, argv);
	
	return Null();
}

static Handle<Value> SessionPropertyGetter(Local<String> name, const AccessorInfo &info) {
	HandleScope scope;

	string n = *String::AsciiValue(name);
	if (n == "mechanism") {
		const char* m = gsasl_mechanism_name(GetSession(info.Holder()));
		return m == NULL ? Null() : String::New(m);
	}

	map<string, Gsasl_property>::iterator it = properties.find(n);
	if (it == properties.end()) {
		return Handle<Value>();
	}

	const char* value = gsasl_property_fast(GetSession(info.Holder()), it->second);
	return value == NULL ? Null() : String::New(value);
}

static Handle<Value> SessionPropertySetter(Local<String> name, Local<Value> value, const AccessorInfo &info) {
	HandleScope scope;

	map<string, Gsasl_property>::iterator it = properties.find(*String::AsciiValue(name));
	if (it == properties.end()) {
		return Handle<Value>();
	}

	gsasl_property_set(GetSession(info.Holder()), it->second, *String::AsciiValue(value));
	return value;
}

static Handle<Array> SessionPropertyEnumerator(const AccessorInfo& info) {
	int index = 0;
	Handle<Array> list = Array::New();
	list->Set(index++, String::New("mechanism"));
	Gsasl_session* session = GetSession(info.Holder());
	for (int p = GSASL_AUTHID; p <= GSASL_CB_TLS_UNIQUE; ++p) {
		if (gsasl_property_fast(session, (Gsasl_property)p) != NULL) {
			list->Set(index++, String::New(propertyNames[p]));
		}
	}
	return list;
}

static Handle<Value> StartClientSession(const Arguments& args) {
	HandleScope scope;

	if (args.Length() < 2) {
		return ThrowException(Exception::Error(String::New("Expecting two arguments")));
	}

	if (!args[0]->IsString()) {
		return ThrowException(Exception::TypeError(String::New("Argument 0 must be a string")));
	}
	
	if (!args[1]->IsFunction()) {
		return ThrowException(Exception::TypeError(String::New("Argument 1 must be a function")));
	}

	Handle<Value> argv[] = { Null(), Null() };
	Gsasl_session* session;
	int rc = gsasl_client_start(ctx, *String::AsciiValue(args[0]), &session);
	if (rc == GSASL_OK) {
		argv[1] = GetSessionObject(session);
	}
	else {
		argv[0] = Exception::Error(String::New(gsasl_strerror(rc)));
	}

	Handle<Function>::Cast(args[1])->Call(args.Holder(), 2, argv);

	return Handle<Value>();
}

static Handle<Value> StartServerSession(const Arguments& args) {
	HandleScope scope;

	if (args.Length() < 2) {
		return ThrowException(Exception::Error(String::New("Expecting two arguments")));
	}

	if (!args[0]->IsString()) {
		return ThrowException(Exception::TypeError(String::New("Argument 0 must be a string")));
	}

	if (!args[1]->IsFunction()) {
		return ThrowException(Exception::TypeError(String::New("Argument 1 must be a function")));
	}

	Handle<Value> argv[] = { Null(), Null() };
	Gsasl_session* session;
	int rc = gsasl_server_start(ctx, *String::AsciiValue(args[0]), &session);
	if (rc == GSASL_OK) {
		argv[1] = GetSessionObject(session);
	}
	else {
		argv[0] = Exception::Error(String::New(gsasl_strerror(rc)));
	}

	Handle<Function>::Cast(args[1])->Call(args.Holder(), 2, argv);

	return Handle<Value>();
}

static Handle<Value> RegisterCallback(const Arguments& args) {
	if (args.Length() < 2) {
		return ThrowException(Exception::Error(String::New("Expecting two arguments")));
	}

	if (!args[0]->IsString()) {
		return ThrowException(Exception::TypeError(String::New("Argument 0 must be a string")));
	}

	if (!args[1]->IsFunction()) {
		return ThrowException(Exception::TypeError(String::New("Argument 1 must be a function")));
	}

	listeners->Set(args[0], args[1]);

	return Handle<Value>();
}

static int InvokePropertyCallback(Gsasl_session* session, Gsasl_property property) {
	HandleScope scope;

	Handle<Value> callback = listeners->Get(String::NewSymbol("property"));
	if (callback->IsFunction()) {
		Handle<Value> argv[] = { String::New(propertyNames[property]) };
		Handle<Value> rv = Handle<Function>::Cast(callback)->Call(module, 1, argv);
		if (rv->IsString()) {
			gsasl_property_set(session, property, *String::AsciiValue(rv));
			return GSASL_OK;
		}
	}

	return GSASL_NO_CALLBACK;
}

static int InvokeValidatonCallback(Gsasl_session* session, const char* name) {
	HandleScope scope;

	Handle<Value> callback = listeners->Get(String::NewSymbol(name));
	if (callback->IsFunction()) {
		Handle<Value> argv[] = { GetSessionObject(session) };
		Handle<Value> rv = Handle<Function>::Cast(callback)->Call(module, 1, argv);
		if (rv->ToBoolean()->Value()) return GSASL_OK;
	}

	return GSASL_NO_CALLBACK;
}

static int Callback(Gsasl* ctx, Gsasl_session* session, Gsasl_property property) {
	if (property >= GSASL_AUTHID && property <= GSASL_CB_TLS_UNIQUE) {
		return InvokePropertyCallback(session, property);
	}

	if (property >= GSASL_VALIDATE_SIMPLE && property <= GSASL_VALIDATE_SECURID) {
		return InvokeValidatonCallback(session, validationNames[property - GSASL_VALIDATE_SIMPLE]);
	}

	return GSASL_NO_CALLBACK;
}

extern "C"
void init(Handle<Object> target) {
	int rc = gsasl_init(&ctx);
	if (rc != GSASL_OK) {
		target->Set(String::NewSymbol("error"),
			Exception::Error(String::New(gsasl_strerror(rc))));
		return;
	}

	module = Persistent<Object>::New(target);
	module.MakeWeak(NULL, ModuleReferenceCallback);

	gsasl_callback_set(ctx, Callback);

	for (int p = GSASL_AUTHID; p <= GSASL_CB_TLS_UNIQUE; ++p) {
		properties[propertyNames[p]] = (Gsasl_property)p;
	}

	Handle<FunctionTemplate> sessionTemplate = FunctionTemplate::New();
	sessionTemplate->SetClassName(String::New("Session"));
	Local<ObjectTemplate> instanceTemplate = sessionTemplate->InstanceTemplate();
	instanceTemplate->SetInternalFieldCount(1);
	instanceTemplate->SetNamedPropertyHandler(SessionPropertyGetter, SessionPropertySetter,
			NULL, NULL, SessionPropertyEnumerator);
	Local<Template> prototypeTemplate = sessionTemplate->PrototypeTemplate();
	prototypeTemplate->Set(String::NewSymbol("step"), FunctionTemplate::New(Step)->GetFunction());

	Session = Persistent<Function>::New(sessionTemplate->GetFunction());
	listeners = Persistent<Object>::New(Object::New());

	target->Set(String::NewSymbol("startClientSession"),
			FunctionTemplate::New(StartClientSession)->GetFunction());
	target->Set(String::NewSymbol("startServerSession"),
			FunctionTemplate::New(StartServerSession)->GetFunction());
	target->Set(String::NewSymbol("on"),
			FunctionTemplate::New(RegisterCallback)->GetFunction());
}
