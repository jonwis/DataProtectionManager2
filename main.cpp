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

winrt::hstring GetImageFilePath()
{
    static winrt::hstring s_imageFilePath;

    if (s_imageFilePath.empty())
    {
        auto picker = FileOpenPicker();
        picker.as<::IInitializeWithWindow>()->Initialize(::GetConsoleWindow());
        picker.FileTypeFilter().Append(L".jpg");
        auto file = picker.PickSingleFileAsync().get();
        s_imageFilePath = file.Path();
    }

    return s_imageFilePath;
}

void TestImageStreamTranscode()
{
    auto wicFactory = winrt::try_create_instance<::IWICImagingFactory>(CLSID_WICImagingFactory);

    DataProtectionProvider scuffles;

    // Pick a file, get a frame decoder for it, and decode the first frame
    winrt::Windows::Storage::Pickers::FileOpenPicker picker;
    wil::com_ptr<::IWICBitmapDecoder> fileDecoder;
    THROW_IF_FAILED(wicFactory->CreateDecoderFromFilename(GetImageFilePath().c_str(), nullptr, GENERIC_READ, WICDecodeOptions{}, &fileDecoder));
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

    // Now we have an encrypted stream, say on a file, and we need to pass it through
    // the decryption filter to produce cleartext.
    auto pngClearText = create_mem_stream();
    {
        auto decoder = scuffles.CreateDecryptionStreamWriter(pngClearText.get());
        wil::stream_set_position(pngEncryptedStream.get(), 0);
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

void TestImageDecodeStreamTranscode()
{
    auto wicFactory = winrt::try_create_instance<::IWICImagingFactory>(CLSID_WICImagingFactory);
    auto pngEncryptedStream = create_mem_stream();

    // Pick a file, get a frame decoder for it, and decode the first frame into a bitmap, then transcode
    // that into a PNG, where the encoded PNG bits are streamed through the encryption writer into the
    // memory buffer temporary.
    {
        wil::com_ptr<::IWICBitmapDecoder> fileDecoder;
        wil::com_ptr<::IWICBitmapFrameDecode> frameDecode;
        THROW_IF_FAILED(wicFactory->CreateDecoderFromFilename(GetImageFilePath().c_str(), nullptr, GENERIC_READ, WICDecodeOptions{}, &fileDecoder));
        THROW_IF_FAILED(fileDecoder->GetFrame(0, &frameDecode));

        DataProtectionProvider scuffles;
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

    // Reset the encrypted stream, then wrap it in a DecryptionReadStream and create a new PNG decoder
    // on that stream, decode the first frame, and get the frame's size.
    {
        wil::stream_set_position(pngEncryptedStream.get(), 0);
        auto readStream = winrt::make_self<DecryptionReadStream>(pngEncryptedStream.get());
        wil::com_ptr<IWICBitmapDecoder> pngDecoder;
        wil::com_ptr<IWICBitmapFrameDecode> pngFrameDecoder;
        wil::com_ptr<IWICBitmap> pngBitmap;
        wil::com_ptr<IWICBitmapLock> pngLock;
        WICRect pngRect{};
        UINT pngDataSize = 0;
        BYTE* pngDataPointer = nullptr;
        THROW_IF_FAILED(wicFactory->CreateDecoderFromStream(readStream.get(), nullptr, WICDecodeOptions{}, &pngDecoder));
        THROW_IF_FAILED(pngDecoder->GetFrame(0, &pngFrameDecoder));
        THROW_IF_FAILED(pngFrameDecoder->GetSize(reinterpret_cast<UINT*>(&pngRect.Width), reinterpret_cast<UINT*>(&pngRect.Height)));
        THROW_IF_FAILED(wicFactory->CreateBitmapFromSource(pngFrameDecoder.get(), {}, &pngBitmap));
        THROW_IF_FAILED(pngBitmap->Lock(&pngRect, WICBitmapLockRead, &pngLock));
        THROW_IF_FAILED(pngLock->GetDataPointer(&pngDataSize, &pngDataPointer));
    }
}

int main()
{
    init_apartment();

    TestBufferProtection();
    TestBinaryStreamEncryption();
    TestImageStreamTranscode();
    TestDecyptionReadStream();
    TestImageDecodeStreamTranscode();
}
