#include "pch.h"
#include <filesystem>

#include "DataProtectionProvider.h"

using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Storage::Pickers;

wil::com_ptr<IStream> create_mem_stream()
{
    wil::com_ptr<IStream> output;
    output.attach(::SHCreateMemStream(nullptr, 0));
    THROW_IF_NULL_ALLOC(output);
    return output;
}

void compare_stream_content(IStream* left, IStream* right)
{
    // Read chunks from the two streams and compare them
    while (true)
    {
        std::array<uint8_t, 4096> leftData;
        std::array<uint8_t, 4096> rightData;

        auto leftRead = wil::stream_read_partial(left, leftData.data(), 4096);
        auto rightRead = wil::stream_read_partial(right, rightData.data(), 4096);

        if (leftRead != rightRead)
        {
            printf("Clear = %d, File = %d\n", leftRead, rightRead);
            return;
        }
        else if (memcmp(leftData.data(), rightData.data(), leftRead) != 0)
        {
            printf("Mismatch in content\n");
            return;
        }

        if (leftRead == 0)
            break;
    }
}

void TestBinaryStreamEncryption()
{
    DataProtectionProvider scuffles;

    auto filePath = wil::GetModuleFileNameW<std::wstring>(nullptr);
    wil::com_ptr<IStream> fileStream;
    THROW_IF_FAILED(::SHCreateStreamOnFileEx(filePath.c_str(), STGM_READ, 0, FALSE, nullptr, &fileStream));

    // Stream all our bytes through the encryption filter, stored in memory
    auto encryptedOutputBuffer = create_mem_stream();
    {
        auto writer = scuffles.CreateEncryptionStreamWriter(encryptedOutputBuffer.get());
        wil::stream_copy_all(fileStream.get(), writer.get());
        writer->finish();
    }

    // Stream the encrypted bytes through a decrypted stream, make sure they match
    auto clearStream = create_mem_stream();
    {
        auto reader = scuffles.CreateDecryptionStreamWriter(clearStream.get());
        wil::stream_set_position(encryptedOutputBuffer.get(), 0);
        wil::stream_copy_all(encryptedOutputBuffer.get(), reader.get());
        reader->finish();
    }

    wil::stream_set_position(clearStream.get(), 0);
    wil::stream_set_position(fileStream.get() , 0);
    compare_stream_content(clearStream.get(), fileStream.get());
}

void TestBufferProtection()
{
    DataProtectionProvider scuffles;
    uint8_t data[] = "scuffles the fluffy kitten";
    auto roundTrip = scuffles.UnprotectBuffer(scuffles.ProtectBuffer(data).as_span<uint8_t>());
    if (roundTrip.size() != sizeof(data))
    {
        printf("Size mismatch, %zd vs %d\n", sizeof(data), roundTrip.size());
    }
    else if (memcmp(roundTrip.data(), data, sizeof(data)) != 0)
    {
        printf("Content mismatch\n");
    }
}

DataProtectionBuffer DeprotectFileToBuffer(std::filesystem::path const& path, DataProtectionProvider& provider)
{
    // Map the file into memory, throw it through the unprotect buffer
    wil::unique_hfile file{ ::CreateFile(path.c_str(), FILE_GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr) };
    LARGE_INTEGER largeSize{};
    THROW_LAST_ERROR_IF(!file);
    THROW_LAST_ERROR_IF(!::GetFileSizeEx(file.get(), &largeSize));
    wil::unique_handle mapped{ ::CreateFileMapping(file.get(), nullptr, PAGE_READONLY, 0, 0, nullptr) };
    THROW_LAST_ERROR_IF(!mapped);
    wil::unique_mapview_ptr<uint8_t const> view{ reinterpret_cast<uint8_t const*>(::MapViewOfFileEx(mapped.get(), FILE_MAP_READ, 0, 0, static_cast<SIZE_T>(largeSize.QuadPart), nullptr)) };
    THROW_LAST_ERROR_IF(!mapped);

    return provider.UnprotectBuffer({ view.get(), static_cast<size_t>(largeSize.QuadPart) });
}

void ProtectBufferToFile(std::span<uint8_t const> data, std::filesystem::path const& path, DataProtectionProvider& provider)
{
    auto buffer = provider.ProtectBuffer(data);
    wil::unique_hfile file{ ::CreateFile(path.c_str(), FILE_GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr) };
    THROW_IF_WIN32_BOOL_FALSE(::WriteFile(file.get(), buffer.data(), static_cast<DWORD>(buffer.size()), nullptr, nullptr));
    THROW_IF_WIN32_BOOL_FALSE(::SetEndOfFile(file.get()));
}

void TestImageStreamTranscode()
{
    auto wicFactory = winrt::try_create_instance<::IWICImagingFactory>(CLSID_WICImagingFactory);

    DataProtectionProvider scuffles;

    // Pick a file, get a frame decoder for it, and decode the first frame
    winrt::Windows::Storage::Pickers::FileOpenPicker picker;
    picker.as<::IInitializeWithWindow>()->Initialize(::GetConsoleWindow());
    picker.FileTypeFilter().Append(L".jpg");
    auto f = picker.PickSingleFileAsync().get();
    wil::com_ptr<::IWICBitmapDecoder> fileDecoder;
    THROW_IF_FAILED(wicFactory->CreateDecoderFromFilename(f.Path().c_str(), nullptr, GENERIC_READ, WICDecodeOptions{}, &fileDecoder));
    wil::com_ptr<::IWICBitmapFrameDecode> frameDecode;
    THROW_IF_FAILED(fileDecoder->GetFrame(0, &frameDecode));

    // Create a memory steam, and an encryption filter on top of that
    auto pngEncryptedStream = create_mem_stream();

    // Encode the JPG into a PNG, where the encoded PNG bits are streamed through the encryption
    // writer into the encrypted stream above.
    {
        auto pngEncrytpedWriter = scuffles.CreateEncryptionStreamWriter(pngEncryptedStream.get());
        wil::com_ptr<::IWICBitmapEncoder> pngEncoder;
        THROW_IF_FAILED(wicFactory->CreateEncoder(GUID_ContainerFormatPng, nullptr, &pngEncoder));
        THROW_IF_FAILED(pngEncoder->Initialize(pngEncrytpedWriter.get(), WICBitmapEncoderCacheOption::WICBitmapEncoderNoCache));
        wil::com_ptr<::IWICBitmapFrameEncode> writeFrame;
        wil::com_ptr<::IPropertyBag2> propertyBag;
        THROW_IF_FAILED(pngEncoder->CreateNewFrame(&writeFrame, &propertyBag));
        THROW_IF_FAILED(writeFrame->Initialize(nullptr));
        THROW_IF_FAILED(writeFrame->WriteSource(frameDecode.get(), nullptr));
        THROW_IF_FAILED(writeFrame->Commit());
        THROW_IF_FAILED(pngEncoder->Commit());
        pngEncrytpedWriter->finish();
    }

    // ... and then let's see what's in the output stream
    wil::stream_set_position(pngEncryptedStream.get(), 0);
    printf("%I64x\n", wil::stream_size(pngEncryptedStream.get()));

    // Now we have an encrypted stream, say on a file, and we need to pass it through
    // the decryption filter to produce cleartext. We don't have a way (yet) to make
    // a "read through" filter, so we _push_ content back through the filter and pass
    // that off to the decoder, temporarily creating a cleartext copy (boo.)
    auto pngClearText = create_mem_stream();
    {
        auto decoder = scuffles.CreateDecryptionStreamWriter(pngClearText.get());
        wil::stream_copy_all(pngEncryptedStream.get(), decoder.get());
        decoder->finish();
    }

    // Create a PNG decoder on the resulting memory stream
    wil::com_ptr<IWICBitmapDecoder> pngDecoder;
    wil::com_ptr<IWICBitmapFrameDecode> pngFrameDecoder;
    wil::com_ptr<IWICBitmap> pngBitmap;
    wil::com_ptr<IWICBitmapLock> pngLock;
    WICRect pngRect{};
    UINT pngDataSize = 0;
    BYTE* pngDataPointer = nullptr;
    wil::stream_set_position(pngClearText.get(), 0);
    THROW_IF_FAILED(wicFactory->CreateDecoderFromStream(pngClearText.get(), nullptr, WICDecodeOptions{}, &pngDecoder));
    THROW_IF_FAILED(pngDecoder->GetFrame(0, &pngFrameDecoder));
    THROW_IF_FAILED(pngFrameDecoder->GetSize(reinterpret_cast<UINT*>(&pngRect.Width), reinterpret_cast<UINT*>(&pngRect.Height)));
    THROW_IF_FAILED(wicFactory->CreateBitmapFromSource(pngFrameDecoder.get(), {}, &pngBitmap));
    THROW_IF_FAILED(pngBitmap->Lock(&pngRect, WICBitmapLockRead, &pngLock));
    THROW_IF_FAILED(pngLock->GetDataPointer(&pngDataSize, &pngDataPointer));

    // TODO: Implement that "read through" filter that on Read passes back decrypted data from a temporary
    // buffer, if the buffer is empty pushes more encrypted data through it. So rather than decrypting the
    // entire thing into memory you get a reasonable-size chunking model
}

void TestDecyptionReadStream()
{
    DataProtectionProvider scuffles;

    // Open the current executable file as a stream, then read from it to produce an encrypted
    // stream
    auto filePath = wil::GetModuleFileNameW<std::wstring>(nullptr);
    wil::com_ptr<IStream> fileStream;
    THROW_IF_FAILED(::SHCreateStreamOnFileEx(filePath.c_str(), STGM_READ, 0, FALSE, nullptr, &fileStream));
    auto encryptedStream = create_mem_stream();
    {
        auto writer = scuffles.CreateEncryptionStreamWriter(encryptedStream.get());
        wil::stream_copy_all(fileStream.get(), writer.get());
        writer->finish();
    }

    // Now wrap a DecryptionReadStream around the encryptedStream and read through it
    // and compare against the orignal fileStream content
    wil::stream_set_position(encryptedStream.get(), 0);
    wil::stream_set_position(fileStream.get(), 0);
    auto readStream = winrt::make_self<DecryptionReadStream>(encryptedStream.get());
    compare_stream_content(readStream.get(), fileStream.get());
}

void EncryptStreamToFile(IStream* source, std::filesystem::path const& path, std::wstring const& cryptDescriptor)
{
    // Open the given file path for write; always create it, we'll trim the size at the end.
    wil::unique_hfile fileHandle{ ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr) };
    THROW_LAST_ERROR_IF(!fileHandle);

    // Create a crypto descriptor handle for the encryption scope passed in.
    NCRYPT_DESCRIPTOR_HANDLE cryptHandle{};
    THROW_IF_WIN32_ERROR(::NCryptCreateProtectionDescriptor(cryptDescriptor.c_str(), 0, &cryptHandle));

    // Set up a pump that pushes decrypted data into the output file opened above. This callback is
    // invoked during the NCryptStreamUpdate operation.
    NCRYPT_PROTECT_STREAM_INFO streamInfo{};
    NCRYPT_STREAM_HANDLE streamHandle{};
    streamInfo.pvCallbackCtxt = fileHandle.get();
    streamInfo.pfnStreamOutput = [](void* context, const BYTE* data, SIZE_T dataSize, BOOL) -> SECURITY_STATUS
        {
            DWORD written;
            auto fileHandle = static_cast<HANDLE>(context);
            RETURN_LAST_ERROR_IF(!::WriteFile(fileHandle, data, static_cast<DWORD>(dataSize), &written, nullptr));
            return ERROR_SUCCESS;
        };

    THROW_IF_WIN32_ERROR(::NCryptStreamOpenToProtect(cryptHandle, NCRYPT_SILENT_FLAG, nullptr, &streamInfo, &streamHandle));

    // Read chunks from the stream until we get less in a block than requested. Push each block
    // through the encryption stream, where the callback above eventuall writes the decrypted
    // block to the file. When we get less in a Read than requested, it's the final block, so
    // let the crypto stream know to finalize any pending bytes.
    auto const readBufferSize = 32 * 1024ul;
    auto readBuffer = std::make_unique<std::array<uint8_t, readBufferSize>>();
    while (true)
    {
        auto const readSize = wil::stream_read_partial(source, readBuffer->data(), readBufferSize);
        auto const finalBlock = readSize < readBufferSize;
        THROW_IF_WIN32_ERROR(::NCryptStreamUpdate(streamHandle, readBuffer->data(), readSize, finalBlock));
        if (finalBlock)
        {
            break;
        }
    }

    // Set the EOF on the file
    THROW_LAST_ERROR_IF(!::SetEndOfFile(fileHandle.get()));
}

winrt::com_ptr<IStream> DecryptFileToStream(std::filesystem::path const& path)
{
    // Context object with the output stream and an error holder; the NCrypt APIs
    // expect Win32 errors, not HRESULTs, so store them off on the side for a bit.
    struct WriteContext {
        winrt::com_ptr<IStream> clearStream{ ::SHCreateMemStream(nullptr, 0), winrt::take_ownership_from_abi };
        HRESULT writeResult{ S_OK };
    } ctx;
    THROW_IF_NULL_ALLOC(ctx.clearStream);

    // Create a decryption stream that will push decrypted bytes into the memory-backed output
    // stream from above. Record any errors along the way for use later.
    NCRYPT_PROTECT_STREAM_INFO streamInfo{};
    NCRYPT_STREAM_HANDLE streamHandle{};
    streamInfo.pvCallbackCtxt = &ctx;
    streamInfo.pfnStreamOutput = [](void* self, const BYTE* data, SIZE_T dataSize, BOOL) -> SECURITY_STATUS
        {
            auto context = static_cast<WriteContext*>(self);
            context->writeResult = wil::stream_write_nothrow(context->clearStream.get(), data, static_cast<unsigned long>(dataSize));
            return SUCCEEDED_LOG(context->writeResult) ? ERROR_SUCCESS : ERROR_GEN_FAILURE;
        };

    THROW_IF_WIN32_ERROR(::NCryptStreamOpenToUnprotect(&streamInfo, 0, nullptr, &streamHandle));

    // Open the input file to read content. Another approach would be to map the file and just
    // point the NCrypt APIs at the mapped memory, eliminating a buffer. But, it's not super
    // clear the size of write-chunks the NCrypt APIs can handle - trying to decrypt a 2gb
    // file might hit memory-size limitations inside that implementation.
    auto const bufferSize = 64 * 1024ul;
    auto readBuffer = std::make_unique<std::array<uint8_t, bufferSize>>();
    wil::unique_hfile fileHandle{ ::CreateFile(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) };
    THROW_LAST_ERROR_IF(!fileHandle);

    while (true)
    {
        // Fetch the next chunk and pass it through the streaming decrypter. When the last byte
        // is read out of the file, it's the final block in the stream, so pass that along.
        // When an error happens inside the write callback, it's recorded in the context - that
        // error overrides any NCrypt API error returned.
        DWORD readSize = 0;
        THROW_LAST_ERROR_IF(!::ReadFile(fileHandle.get(), readBuffer->data(), bufferSize, &readSize, nullptr));
        bool const finalBlock = (readSize == 0);
        auto const statusResult = ::NCryptStreamUpdate(streamHandle, readBuffer->data(), readSize, finalBlock);
        if (statusResult != ERROR_SUCCESS)
        {
            THROW_IF_FAILED(ctx.writeResult);
            THROW_WIN32(statusResult);
        }
        else if (finalBlock)
        {
            break;
        }
    }

    // Move the position of the stream back to zero so the next read sees all the decrypted content
    // and return it out of the temporary context object.
    wil::stream_set_position(ctx.clearStream.get(), 0);
    return std::move(ctx.clearStream);
}

// Return a new stream over the current executable module as something to try encrypting and
// decrypting it.
winrt::com_ptr<IStream> GenerateTestStream()
{
    winrt::com_ptr<IStream> fileStream;
    THROW_IF_FAILED(::SHCreateStreamOnFileW(wil::GetModuleFileNameW().get(), STGM_READ, fileStream.put()));
    return fileStream;
}

void TestEncryptToFileReadFromFile()
{
    std::filesystem::path tempPath{ wil::ExpandEnvironmentStringsW(L"%temp%\\test-temp-file.bin").get() };
    auto deleter = wil::scope_exit([&] {
        std::filesystem::remove(tempPath);
    });
    auto sourceStream = GenerateTestStream();

    EncryptStreamToFile(sourceStream.get(), tempPath, L"local=user");
    auto decrypted = DecryptFileToStream(tempPath);

    wil::stream_set_position(sourceStream.get(), 0);
    wil::stream_set_position(decrypted.get(), 0);
    compare_stream_content(sourceStream.get(), decrypted.get());
}

int main()
{
    init_apartment();
 
    TestBufferProtection();
    TestBinaryStreamEncryption();
    TestImageStreamTranscode();
    TestDecyptionReadStream();
    TestEncryptToFileReadFromFile();
}
