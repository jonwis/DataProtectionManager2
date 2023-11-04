# DataProtectionManager2

This sample demonstrates how to use the `NCryptProtect..` methods directly instead of through the
[DataProtectionProvider](https://learn.microsoft.com/uwp/api/windows.security.cryptography.dataprotection.dataprotectionprovider?view=winrt-22621)
types. Under the covers, `DataProtectionProvider` passes buffers and streams through the equivalent
`NCryptProtect...` methods.  Using the Win32 APIs directly reduces async threading cost and makes
a write-through-filter available for producing a protected stream directly.

## DecryptionReadStream

Wraps `NCryptStreamOpenToUnprotect` into a C++ type with helper methods. It is-an `IStream` that
supports reading from a stream containing ciphertext and producing cleartext. Most of the other
IStream methods are not implemented. The source stream should have been created with
`CreateEncryptionStreamWriter` or generally `NCryptStreamOpenToProtect`.

```c++
// Open a file stream containing protected content, and wrap it in a decryption stream. Pass it
// to the WIC imaging APIs to decode the image as a jpeg.
wil::com_ptr<IStream> fileStream = open_stream_on_file(...);
wil::com_ptr<IStream> winrt::make<DecryptionReadStream>(fileStream.get());

auto wicFactory = winrt::create_instance<IWICImagingFactory>(CLSID_WICImagingFactory);
wil::com_ptr<IWICBitmapDecoder> decoder;
wil::com_ptr<IWICBitmapFrameDecode> frame;
winrt::check_hresut(wicFactory->CreateDecoderFromStream(decryptionStream.get(), nullptr, WICDecodeMetadataCacheOnDemand, decoder.put()));
winrt::check_hresult(decoder->GetFrame(0, frame.put()));
winrt::check_hresult(frame->GetSize(&width, &height));
```

## DataProtectionProvider

Wraps `NCryptCreateProtectionDescriptor` into a C++ type with helper methods. Its constructor
defaults to the `"LOCAL=user"` scope, which means "protect with a key that is local to this
user on this machine." You can provide [any other scope](https://learn.microsoft.com/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptcreateprotectiondescriptor)
that meets your needs.

### DataProtectionProvider::ProtectBuffer

Takes in a cleartext `byte` (really, uint8_t) span and produces a `DataProtectionBuffer` containing
ciphertext by calling [`NCryptProtectSecret`](https://learn.microsoft.com/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptprotectsecret).
The returned buffer owns the allocation until discarded.

```c++
// Serialize the JSON to a utf8 string, then pass it through the protector, and write
// the results to a file.
MyJsonObject j = /* ... */;
std::string utf8 = j.ToUtf8String();
DataProtectionProvider protector;
auto clearContent = protector.UnprotectBuffer({utf8.c_str(), utf8.size()});
WriteFileContent(clearContent.data(), clearContent.size());
```

### DataProtectionBuffer::UnprotectBuffer

Takes in a buffer produced by `ProtectBuffer` as a span, and produces a `DataProtectionBuffer`
containing cleartext by calling [`NCryptUnprotectSecret`](https://learn.microsoft.com/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptunprotectsecret).
The returned buffer owns the allocation until discarded.

```c++
std::vector<uint8_t> fileData = /* raw bits that are protected  as above */;
DataProtectionProvider protector;
auto clearContent = protector.UnprotectBuffer({fileData.data(), fileData.size()});
auto j = MyJsonObject::FromUtf8(clearContent.as_span<uint8_t>());
```

### DataProtectionBuffer::CreateEncryptionStreamWriter

Wraps an "output" (lower) stream with a new `IStream` interface that encrypts data before flushing
it to the lower stream. Useful for passing to things that produce a stream output to write somewhere,
like to a file on the filesystem. As with many encryption primitives, be sure to call `stream->finish()`
to signal the terminal block in the stream.

```c++
// In this example, the myThing instance writes itself to the IStream in whatever means it
// desires, but the output to the file on disk is protected.
wil::com_ptr<IStream> fileStream = create_file_as_stream(...);
DataProtectionProvider protector;
auto writer = protector.CreateEncryptionStreamWriter(fileStream.get());
auto myThing = /* ... */;
myThing.SerializeToStream(writer.get());
writer->finish();
```

### DataProtectionBuffer::CreateDecryptionStreamWriter

Wraps an "output" (lower) stream with a new `IStream` interface that decrypts data before flushing it
to the lower stream. Useful for filling a stream with cleartext content before passing the stream
on to something to process. As with many encryption primitives, be sure to call `stream->finish()`
to signal the last block in the stream.

```c++
// In this example, the source IStream is on the file produced above, and we want to get the
// decrypted bytes to deserialize a thing.
wil::com_ptr<IStream> fileStream = open_stream_on_file(...);
wil::com_ptr<IStream> memStream = create_memory_stream();
DataProtectionProvider protector;
auto writer = protector.CreateDecryptionStreamWriter(memStream.get());
wil::stream_copy_all(fileStream.get(), writer.get());
writer->finish();
wil::stream_set_position(memStream.get(), 0);
auto myThing = MyThing::DeserializeFromStream(memStream.get());
```

## Compatibility

Note that the the binary formats produced by `NCryptProtectSecret` and `NCryptStreamOpenToProtect` are
not compatible. That is, you cannot take a buffer produced by `NCryptProtectSecret` (or `DataProtectionManager::ProtectBuffer`)
and pass it to `NCryptStreamOpenToUnprotect` (or `DataProtectionManager::CreateDecryptionStreamWriter`).
If you are using these methods to produce files, consider using the file extension to know which
decoding method to use.

## TODO

### File output helpers

Provide a mechanism to set up a "safe storage" root, with the following operations:

* Write buffer to file - takes a `std::span` and encodes it to a named file in the store
* Read named buffer - takes a file name and returns a decoded buffer from it
* Get write-mode stream on file - returns an `IStream` that just writes to a file
* Get read-mode stream on file - returns an `IStream` which, when read, decrypts the content

### Custom key management

Provide "sub user" control over the content in the protected storage. Use methods like
`NCryptRegisterProtectionDescriptorName` to manage (create, remove) scopes for this app.